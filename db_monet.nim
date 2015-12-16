#
#
#            Monetdb Library for Nim
#        (c) Copyright 2015 Metatexx GmbH
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

import times, net, nimSHA2, sha1, md5, strutils, parseutils
import db_common
export db_common

type
  DbConnState = enum
    MAPI_STATE_INIT, # MAPI connection is NOT established.
    MAPI_STATE_READY # MAPI connection is established.

  DbConn* = ref object ## \
    ## DbConn is a MonetDB's MAPI connection handle.
    hostname: string
    port:     int
    username: string
    password: string
    database: string
    language: string
    state: DbConnState
    conn: Socket

  DbResult = object
    lastInsertId: int
    rowsAffected: int

  Value* = string

  Row* = seq[string]  ## a row of a dataset. NULL database values will be
                      ## transformed always to nil strings.

  InstantRow* = Row   ## For now an alias to ``Row``. Provided so
                      ## that db_monet adheres to Nim db* interface.

  Rows* = object
    active: bool
    queryId: int
    rowNum:      int
    offset:      int
    lastRowId:   int
    rowCount:    int
    rows: seq[seq[Value]]
    description: seq[Description]
    columns: seq[string]

  Description = object
    columnName:   string
    columnType:   string
    displaySize:  int
    internalSize: int
    precision:    int
    scale:        int
    nullOk:       int

  Stmt = object
    execId: int
    lastRowId:   int
    rowCount:    int
    queryId:     int
    offset:      int
    columnCount: int
    rows:        seq[seq[Value]]
    description: seq[Description]

const
  mapi_MAX_PACKAGE_LENGTH = (1024 * 8) - 2

  mapi_MSG_PROMPT   = ""
  mapi_MSG_INFO     = "#"
  mapi_MSG_ERROR    = "!"
  mapi_MSG_Q        = "&"
  mapi_MSG_QTABLE   = "&1"
  mapi_MSG_QUPDATE  = "&2"
  mapi_MSG_QSCHEMA  = "&3"
  mapi_MSG_QTRANS   = "&4"
  mapi_MSG_QPREPARE = "&5"
  mapi_MSG_QBLOCK   = "&6"
  mapi_MSG_HEADER   = "%"
  mapi_MSG_TUPLE    = "["
  mapi_MSG_REDIRECT = "^"
  mapi_MSG_OK       = "=OK"
  mapi_MSG_MORE = "\1\2\10"

proc newMapi(hostname: string; port: int;
             username, password, database, language: string): DbConn =
  ## Returns a MonetDB's MAPI connection handle.
  ##
  ## To establish the connection, call the Connect() proc.
  DbConn(
    hostname: hostname,
    port:     port,
    username: username,
    password: password,
    database: database,
    language: language,
    state: MAPI_STATE_INIT
  )

proc getBytes(c: DbConn; count: int): string =
  # getBytes reads the given amount of bytes.
  result = newStringOfCap(count)
  let x = c.conn.recv(result, count)
  if x != count:
    dbError("received " & $x & " bytes, but expected " & $count)

proc getBlock(c: DbConn): string =
  # getBlock retrieves a block of message.
  result = ""
  var last = 0
  while last != 1:
    var unpacked: uint16
    let r = c.conn.recv(addr unpacked, 2)
    if r != 2:
      dbError("received " & $r & " bytes, but expected 2")

    let length = unpacked.int shr 1
    last = unpacked.int and 1

    let d = c.getBytes(length)
    result.add(d)

proc putBlock(c: DbConn; b: string) =
  # putBlock sends the given data as one or more blocks.
  var pos = 0
  var last = 0
  while last != 1:
    let xend = min(pos + mapi_MAX_PACKAGE_LENGTH, b.len)
    let length = xend-pos
    if length < mapi_MAX_PACKAGE_LENGTH:
      last = 1
    var packed = uint16((length shl 1) + last)
    if c.conn.send(addr packed, 2) != 2:
      dbError("could not send 2 header bytes")
    if c.conn.send(unsafeAddr b[pos], length) != length:
      dbError("could not send data")
    pos += length

# Disconnect closes the connection.
proc disconnect(c: DbConn) =
  c.state = MAPI_STATE_INIT
  if c.conn != nil:
    c.conn.close()
    c.conn = nil

# Cmd sends a MAPI command to MonetDB.
proc cmd(c: DbConn; operation: string): string =
  if c.state != MAPI_STATE_READY:
    dbError("Database not connected")

  c.putBlock(operation)
  let resp = c.getBlock()
  if len(resp) == 0:
    dbError("empty response")
  elif startsWith(resp, mapi_MSG_OK):
    return resp.substr(3)
  elif resp == mapi_MSG_MORE:
    # tell server it isn't going to get more
    return c.cmd("")
  elif startsWith(resp, mapi_MSG_Q) or
       startsWith(resp, mapi_MSG_HEADER) or
       startsWith(resp, mapi_MSG_TUPLE):
    return resp
  elif startsWith(resp, mapi_MSG_ERROR):
    dbError("Operational error: " & resp.substr(1))
  else:
    dbError("Unknown state: " & resp)

proc challengeResponse(c: DbConn; challenge: string): string =
  let t = split(challenge, ":")
  let
    salt = t[0]
    protocol = t[2]
    hashes = t[3]
    algo = t[5]

  if protocol != "9":
    dbError("We only speak protocol v9")

  if algo != "SHA512":
    # TODO support more algorithm
    dbError("Unsupported algorithm: " & algo)

  var sha = initSHA[SHA512]()
  sha.update(c.password)
  let p = sha.final().toHex().toLower()

  let shashes = "," & hashes & ","
  var pwhash: string
  if contains(shashes, ",SHA1,"):
    pwhash = "{SHA1}" & sha1.compute(p & salt).toHex()
  elif contains(shashes, ",MD5,"):
    pwhash = "{MD5}" & getMD5(p & salt)
  else:
    dbError("Unsupported hash algorithm required for login " & hashes)
  result = "BIG:$#:$#:$#:$#:" % [c.username, pwhash, c.language, c.database]

proc login(c: DbConn; attempts=0) {.gcsafe, locks: 0.}

proc connect(c: DbConn) =
  ## Connect starts a MAPI connection to MonetDB server.
  if c.conn != nil:
    c.conn.close()
    c.conn = nil

  var sock = newSocket()
  sock.connect(c.hostname, Port(c.port))
  sock.setSockOpt(OptKeepAlive, true)
  c.conn = sock
  c.login()

proc login(c: DbConn; attempts=0) =
  let challenge = c.getBlock()

  let response = c.challengeResponse(challenge)
  c.putBlock(response)

  let bprompt = c.getBlock()

  let prompt = strutils.strip(bprompt)
  if len(prompt) == 0:
    discard "Empty response, server is happy"
  elif prompt == mapi_MSG_OK:
    discard "pass"
  elif startsWith(prompt, mapi_MSG_INFO):
    # TODO log info
    discard
  elif startsWith(prompt, mapi_MSG_ERROR):
    # TODO log error
    dbError("Database error: " & prompt.substr(1))
  elif startsWith(prompt, mapi_MSG_REDIRECT):
    let t = split(prompt, " ")
    let r = split(t[0].substr(1), ":")
    if r[1] == "merovingian":
      # restart auth
      if attempts <= 10:
        c.login(attempts + 1)
      else:
        dbError("Maximal number of redirects reached (10)")
    elif r[1] == "monetdb":
      c.hostname = r[2].substr(2)
      let t = split(r[3], "/")
      c.port = parseInt(t[0])
      c.database = t[1]
      c.conn.close()
      c.connect()
    else:
      dbError("Unknown redirect: " & prompt)
  else:
    dbError("Unknown state: " & prompt)
  c.state = MAPI_STATE_READY

proc close(s: Stmt) = discard

proc rawExecute(c: DbConn; q: string): string = c.cmd("s" & q & ";")

const
  mdb_CHAR      = "char"    # (L) character string with length L
  mdb_VARCHAR   = "varchar" # (L) string with atmost length L
  mdb_CLOB      = "clob"
  mdb_BLOB      = "blob"
  mdb_DECIMAL   = "decimal"  # (P,S)
  mdb_SMALLINT  = "smallint" # 16 bit integer
  mdb_INT       = "int"      # 32 bit integer
  mdb_BIGINT    = "bigint"   # 64 bit integer
  mdb_SERIAL    = "serial"   # special 64 bit integer sequence generator
  mdb_REAL      = "real"     # 32 bit floating point
  mdb_DOUBLE    = "double"   # 64 bit floating point
  mdb_BOOLEAN   = "boolean"
  mdb_DATE      = "date"
  mdb_TIME      = "time"      # (T) time of day
  mdb_TIMESTAMP = "timestamp" # (T) date concatenated with unique time
  mdb_INTERVAL  = "interval"  # (Q) a temporal interval

  mdb_MONTH_INTERVAL = "month_interval"
  mdb_SEC_INTERVAL   = "sec_interval"
  mdb_WRD            = "wrd"
  mdb_TINYINT        = "tinyint"

  # Not on the website:
  mdb_SHORTINT    = "shortint"
  mdb_MEDIUMINT   = "mediumint"
  mdb_LONGINT     = "longint"
  mdb_FLOAT       = "float"
  mdb_TIMESTAMPTZ = "timestamptz"

  # full names and aliases, spaces are replaced with underscores
  mdb_CHARACTER               = mdb_CHAR
  mdb_CHARACTER_VARYING       = mdb_VARCHAR
  mdb_CHARACHTER_LARGE_OBJECT = mdb_CLOB
  mdb_BINARY_LARGE_OBJECT     = mdb_BLOB
  mdb_NUMERIC                 = mdb_DECIMAL
  mdb_DOUBLE_PRECISION        = mdb_DOUBLE

proc columns(r: var Rows): seq[string] =
  if r.columns == nil:
    newSeq(r.columns, len(r.description))
    for i, d in pairs(r.description):
      r.columns[i] = d.columnName
  result = r.columns

proc close(r: var Rows) =
  r.active = false

proc parseTuple(s: Stmt, d: string): seq[Value] =
  let L = len(s.description)
  newSeq(result, L)
  var i = 0
  for value in split(d.substr(1, d.len-2), ",\t"):
    if i > L:
      dbError("Length of row doesn't match header")
    result[i] = value
    inc i

proc updateDescription(s: var Stmt, columnNames, columnTypes: openarray[string],
                       displaySizes, internalSizes,
                       precisions, scales, nullOks: openarray[int]) =
  if s.description.isNil:
    newSeq(s.description, len(columnNames))
  else:
    setLen(s.description, len(columnNames))
  for i in 0..high(columnNames):
    s.description[i] = Description(
      columnName:   columnNames[i],
      columnType:   columnTypes[i],
      displaySize:  displaySizes[i],
      internalSize: internalSizes[i],
      precision:    precisions[i],
      scale:        scales[i],
      nullOk:       nullOks[i])

proc parseValue(r: string; a, b: int): string =
  if r[a] == '"':
    result = newStringOfCap(b-a-1)
    var i = a+1
    while i < b:
      case r[i]
      of '\\':
        case r[i+1]:
        of 'x':
          inc i
          var c: int
          i += parseutils.parseHex(r, c, i)
          result.add(chr(c))
          inc(i, 2)
        of '\\':
          result.add('\\')
        of '\'':
          result.add('\'')
        of '\"':
          result.add('\"')
        of 't':
          result.add('\t')
        of 'n':
          result.add('\L')
        else: dbError("unkown escape sequence: \\" & r[i+1])
        inc(i)
      else:
        result.add(r[i])
      inc i
  else:
    result = r.substr(a, b)
    if result == "NULL": result = nil

proc parseSingleRow(r: string; start: int; row: var Row): int =
  var i = start
  while i < r.len-1 and not (r[i] == '\L' and r[i+1] == '['): inc i
  inc i, 2
  var k = i
  while i < r.len:
    if r[i] == ',' and r[i+1] == '\t':
      row.add r.parseValue(k, i-1)
      k = i+2
      inc i, 2
    elif r[i] == ']':
      row.add r.parseValue(k, i-2)
      inc i
      break
    else:
      inc i
  result = i

proc `$`*(r: Row): string =
  var L = (r.len-1) * 2
  for i in 0..r.high: L += (if r[i].isNil: 3 else: r[i].xlen)
  result = newStringOfCap(L)
  for i in 0..r.high:
    if i > 0: result.add ", "
    if r[i].isNil: result.add "nil"
    else: result.add r[i]

proc parseUpdateResult(r: string; start: int;
                       rowCount, lastRowId: var BiggestInt): int =
  var i = start
  while i < r.len and not
    (r[i] == '\L' and r[i+1] == '&' and r[i+2] == '2'): inc i
  inc i, 3
  if i < r.len:
    let L = parseBiggestInt(r, rowCount, i)
    if L > 0:
      inc i, L
      i += parseBiggestInt(r, lastRowId, i)
  result = i

proc storeResult(s: var Stmt; r: string) =
  var columnNames: seq[string]
  var columnTypes: seq[string]
  var displaySizes: seq[int]
  var internalSizes: seq[int]
  var precisions: seq[int]
  var scales: seq[int]
  var nullOks: seq[int]

  for line in splitLines(r):
    if startsWith(line, mapi_MSG_INFO):
      discard "TODO log"
    elif startsWith(line, mapi_MSG_QPREPARE):
      let t = split(strutils.strip(line.substr(2)), " ")
      s.execId = parseInt(t[0])
      return
    elif startsWith(line, mapi_MSG_QTABLE):
      let t = split(strutils.strip(line.substr(2)), " ")
      s.queryId = parseInt(t[0])
      s.rowCount = parseInt(t[1])
      s.columnCount = parseInt(t[2])

      columnNames = newSeq[string](s.columnCount)
      columnTypes = newSeq[string](s.columnCount)
      displaySizes = newSeq[int](s.columnCount)
      internalSizes = newSeq[int](s.columnCount)
      precisions = newSeq[int](s.columnCount)
      scales = newSeq[int](s.columnCount)
      nullOks = newSeq[int](s.columnCount)
    elif startsWith(line, mapi_MSG_TUPLE):
      let v = s.parseTuple(line)
      s.rows.add v
    elif startsWith(line, mapi_MSG_QBLOCK):
      s.rows = newSeq[seq[Value]](0)
    elif startsWith(line, mapi_MSG_QSCHEMA):
      s.offset = 0
      s.rows = newSeq[seq[Value]](0)
      s.lastRowId = 0
      s.description = nil
      s.rowCount = 0
    elif startsWith(line, mapi_MSG_QUPDATE):
      let t = split(strutils.strip(line.substr(2)), " ")
      s.rowCount = parseInt(t[0])
      s.lastRowId = parseInt(t[1])
    elif startsWith(line, mapi_MSG_QTRANS):
      s.offset = 0
      s.rows = newSeq[seq[Value]](0)
      s.lastRowId = 0
      s.description = nil
      s.rowCount = 0
    elif startsWith(line, mapi_MSG_HEADER):
      let t = split(line.substr(1), "#")
      let data = strutils.strip(t[0])
      let identity = strutils.strip(t[1])

      var values = newSeq[string]()
      for value in split(data, ','):
        values.add strutils.strip(value)

      if identity == "name":
        columnNames = values
      elif identity == "type":
        columnTypes = values
      elif identity == "typesizes":
        var sizes = newSeq[seq[int]](len(values))
        for i, value in pairs(values):
          var s = newSeq[int](0)
          for v in split(value, " "):
            s.add parseInt(v)
          internalSizes[i] = s[0]
          sizes.add s
        for j, t in pairs(columnTypes):
          if t == "decimal":
            precisions[j] = sizes[j][0]
            scales[j] = sizes[j][1]
      s.updateDescription(columnNames, columnTypes, displaySizes,
        internalSizes, precisions, scales, nullOks)
      s.offset = 0
      s.lastRowId = 0
    elif line.startsWith mapi_MSG_PROMPT:
      discard "nothing to do"
    elif line.startsWith mapi_MSG_ERROR:
      dbError("Database error: " & line.substr(1))
    else:
      dbError("Unknown state: " & r)

const
  c_ARRAY_SIZE = 100

proc fetchNext(db: DbConn; r: var Rows) =
  if r.rowNum >= r.rowCount:
    return

  r.offset += len(r.rows)
  let xend = min(r.rowCount, r.rowNum+c_ARRAY_SIZE)
  let amount = xend - r.offset

  let cmd0 = "Xexport $# $# $#" % [$r.queryId, $r.offset, $amount]
  discard db.cmd(cmd0)

  #r.storeResult(res) XXX
  #r.rows = r.stmt.rows
  #r.description = r.stmt.description

proc next(db: DbConn; r: var Rows; dest: var seq[Value]) =
  if not r.active:
    dbError("Rows closed")
  if r.queryId == -1:
    dbError("Query didn't result in a resultset")
  if r.rowNum >= r.rowCount:
    # EOF:
    return
  if r.rowNum >= r.offset+len(r.rows):
    db.fetchNext(r)

  for i, v in mpairs(r.rows[r.rowNum-r.offset]):
    dest[i] = v
  r.rowNum += 1

proc dbQuote(s: string; result: var string) =
  if s.isNil:
    result.add "NULL"
  else:
    add(result, '\'')
    for c in items(s):
      case c
      of '\\': add(result, "\\\\")
      of '\'': add(result, "\\'")
      else: add(result, c)
    add(result, '\'')

proc dbQuote*(s: string): string =
  ## DB quotes the string.
  result = newStringOfCap(s.len)
  dbQuote(s, result)

proc dbFormat(formatstr: SqlQuery, args: varargs[string]): string =
  # XXX implement query caching!
  result = ""
  var a = 0
  for c in items(string(formatstr)):
    if c == '?':
      dbQuote(args[a], result)
      inc(a)
    else:
      add(result, c)

proc exec*(db: DbConn, query: SqlQuery, args: varargs[string, `$`]) =
  ## executes the query and raises DbError if not successful.
  let q = dbFormat(query, args)
  let rawResult = db.rawExecute(q)
  #echo q #rawResult
  if rawResult[0] == '!':
    dbError("Database error: " & rawResult.substr(1))
  else:
    let x = rawResult.find("\L!")
    if x >= 0:
      dbError("Database error: " & rawResult.substr(x+2))

proc tryExec*(db: DbConn, query: SqlQuery,
              args: varargs[string, `$`]): bool =
  ## tries to execute the query and returns true if successful, false otherwise.
  try:
    db.exec(query, args)
    result = true
  except DbError:
    result = false

iterator fastRows*(db: DbConn, query: SqlQuery,
                   args: varargs[string, `$`]): Row =
  ## Executes the query and iterates over the result dataset.
  ##
  ## This is very fast, but potentially dangerous.  Use this iterator only
  ## if you require **ALL** the rows.
  ##
  ## Breaking the fastRows() iterator during a loop will cause the next
  ## database query to raise an [EDb] exception ``unable to close due to ...``.
  let q = dbFormat(query, args)

  let rawResult = db.rawExecute(q)
  var i = 0
  var result: Row = @[]
  while true:
    result.setLen 0
    i = parseSingleRow(rawResult, i, result)
    if i >= rawResult.len: break
    yield result

proc getRow*(db: DbConn, query: SqlQuery,
             args: varargs[string, `$`]): Row =
  ## retrieves a single row. If the query doesn't return any rows, this proc
  ## will return a Row with empty strings for each column.
  let q = dbFormat(query, args)
  let rawResult = db.rawExecute(q)
  var i = 0
  result = @[]
  discard parseSingleRow(rawResult, i, result)

proc getAllRows*(db: DbConn, query: SqlQuery,
                 args: varargs[string, `$`]): seq[Row] =
  ## executes the query and returns the whole result dataset.
  result = @[]
  for r in fastRows(db, query, args):
    result.add(r)

iterator rows*(db: DbConn, query: SqlQuery,
               args: varargs[string, `$`]): Row =
  ## same as `FastRows`, but slower and safe.
  for r in fastRows(db, query, args): yield r

iterator instantRows*(db: DbConn, query: SqlQuery,
                      args: varargs[string, `$`]): InstantRow =
  ## same as fastRows but returns a handle that can be used to get column text
  ## on demand using []. Returned handle is valid only within the iterator body.
  for r in fastRows(db, query, args): yield r

proc setTypeName(t: var DbType; name: string) =
  shallowCopy(t.name, name)
  case name
  of "int":
    t.kind = dbInt
    t.size = 4
  of "char":
    t.kind = dbFixedChar
  of "varchar":
    t.kind = dbVarchar
  of "clob", "blob":
    t.kind = dbBlob
  of "decimal":
    t.kind = dbDecimal
  of "tinyint":
    t.kind = dbInt
    t.size = 1
  of "smallint", "shortint":
    t.kind = dbInt
    t.size = 2
  of "bigint":
    t.kind = dbInt
    t.size = 8
  of "hugeint":
    t.kind = dbInt
    t.size = 16
  of "serial":
    t.kind = dbSerial
    t.size = 8
  of "real", "float":
    t.kind = dbFloat
    t.size = 4
  of "double":
    t.kind = dbFloat
    t.size = 8
  of "boolean":
    t.kind = dbBool
    t.size = 1
  of "date":
    t.kind = dbDate
  of "time":
    t.kind = dbTime
  of "timestamp", "timestamptz":
    t.kind = dbTimestamp
  of "interval", "month_interval", "sec_interval":
    t.kind = dbTimeInterval
  else:
    t.kind = dbUnknown

proc parseColumnInfo(r: string; columns: var DbColumns) =
  # Example input:
  # &1 0 6 2 6
  # % voc.test,  voc.test # table_name
  # % id,  data # name
  # % int,  varchar # type
  # % 2,  30 # length
  var i = r.find("\L%")
  if i < 0: return
  inc i
  var tableNames, names, types, typesizes, lens: (int, int)
  while r[i] == '%':
    inc i
    while r[i] == ' ': inc i
    var lineEnd = i
    while lineEnd < r.len-1 and r[lineEnd] != '\L': inc lineEnd
    var hash = lineEnd
    while hash > 0 and r[hash] != '#': dec(hash)
    if hash > 0:
      case r.substr(hash+2, lineEnd-1)
      of "table_name": tableNames = (i, hash-2)
      of "name": names = (i, hash-2)
      of "type": types = (i, hash-2)
      of "typesizes": typesizes = (i, hash-2)
      of "length": lens = (i, hash-2)
      else: discard
    i = lineEnd+1
  #echo r
  #echo tableNames, " ", names, " ", types, " ", typesizes, " ", lens
  var n = names[0]
  var cols = 0

  proc colEnd(r: string; b: var((int, int))): string =
    var i = b[0]
    if i == 0: return ""
    while i < b[1] and r[i+1] != ',': inc i
    result = r.substr(b[0], i)
    #echo "##", result, "##"
    inc i, 2 # skip comma
    while i < b[1] and r[i] == '\t': inc i
    b[0] = i

  while names[0] < names[1]:
    if cols >= columns.len:
      setLen(columns, cols+1)
    setTypeName columns[cols].typ, r.colEnd(types)
    columns[cols].name = r.colEnd(names)
    columns[cols].tableName = r.colEnd(tableNames)
    let sizeAsStr = r.colEnd(lens)
    if sizeAsStr.len > 0 and columns[cols].typ.kind != dbInt:
      columns[cols].typ.size = parseInt(sizeAsStr)
    let typeSizesAsStr = r.colEnd(typesizes)
    if typeSizesAsStr.len > 0:
      var i = parseInt(typeSizesAsStr, columns[cols].typ.precision, 0)
      while typeSizesAsStr[i] == ' ': inc i
      discard parseInt(typeSizesAsStr, columns[cols].typ.scale, i)
    inc cols

iterator instantRows*(db: DbConn; columns: var DbColumns; query: SqlQuery;
                      args: varargs[string, `$`]): InstantRow =
  ## also returns column information at the same time.
  let q = dbFormat(query, args)
  let rawResult = db.rawExecute(q)
  parseColumnInfo(rawResult, columns)
  var i = 0
  var result: Row = @[]
  while true:
    result.setLen 0
    i = parseSingleRow(rawResult, i, result)
    if i >= rawResult.len: break
    yield result

proc getValue*(db: DbConn, query: SqlQuery,
               args: varargs[string, `$`]): string =
  ## executes the query and returns the first column of the first row of the
  ## result dataset. Returns nil if the dataset contains no rows or the database
  ## value is NULL.
  let q = dbFormat(query, args)
  let r = db.rawExecute(q)
  var i = 0
  while i < r.len and not (r[i] == '\L' and r[i+1] == '['): inc i
  inc i, 2
  var k = i
  while i < r.len:
    if r[i] == ',' and r[i+1] == '\t' or r[i] == ']':
      return r.substr(k, i-1)
    inc i

proc tryInsertID*(db: DbConn, query: SqlQuery,
                  args: varargs[string, `$`]): int64 =
  ## executes the query (typically "INSERT") and returns the
  ## generated ID for the row or -1 in case of an error.
  let q = dbFormat(query, args)
  let rawResult = db.rawExecute(q)
  result = -1
  var rowCount: BiggestInt
  discard rawResult.parseUpdateResult(0, rowCount, result)

proc insertID*(db: DbConn, query: SqlQuery,
               args: varargs[string, `$`]): int64 =
  ## executes the query (typically "INSERT") and returns the
  ## generated ID for the row. For Postgre this adds
  ## ``RETURNING id`` to the query, so it only works if your primary key is
  ## named ``id``.
  result = tryInsertID(db, query, args)
  if result < 0: dbError("query failed: " & query.string)

proc execAffectedRows*(db: DbConn, query: SqlQuery,
                       args: varargs[string, `$`]): int64 =
  ## executes the query (typically "UPDATE") and returns the
  ## number of affected rows.
  let q = dbFormat(query, args)
  let rawResult = db.rawExecute(q)
  result = -1
  var lastId: BiggestInt
  discard rawResult.parseUpdateResult(0, result, lastId)

proc close*(db: DbConn) {.tags: [DbEffect].} =
  ## closes the database connection.
  db.disconnect()

proc open*(connection, user, password, database: string): DbConn =
  let x = connection.find(':')
  if x >= 0:
    result = newMapi(hostname = connection.substr(0, x-1),
                     port = parseInt(connection.substr(x+1)),
                     username = user,
                     password = password,
                     database = database,
                     language = "sql")
  else:
    result = newMapi(hostname = connection,
                     port = 50_000,
                     username = user,
                     password = password,
                     database = database,
                     language = "sql")
  result.connect()


proc setEncoding*(connection: DbConn, encoding: string): bool {.
  tags: [DbEffect].} =
  ## sets the encoding of a database connection, returns true for
  ## success, false for failure.
  ##
  ## For Monet DB this is not supported and it always returns false.
  return false
