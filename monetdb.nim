
import times, net, nimSHA2, sha1, md5, strutils

type
  DbError* = object of IOError ## exception that is raised if a database error occurs

  Time* = object ## Time represents MonetDB's Time datatype.
    hour*, min*, sec*: int
  Date* = object ## Time represents MonetDB's Date datatype.
    year*:  int
    month*: int
    day*:   int

  Conn* = object
    config*: Config
    mapi*:   MapiConn

  Config* = ref object
    username*: string
    password*: string
    hostname*: string
    database*: string
    port*:     int

  MapiConn* = ref object ## \
    ## MapiConn is a MonetDB's MAPI connection handle.
    ##
    ## The values in the handle are initially set according to the values
    ## that are provided when calling newMapi(). However, they may change
    ## depending on how the MonetDB server redirects the connection.
    ## The final values are available after the connection is made by
    ## calling the connect() proc.
    ##
    ## The State value can be either MAPI_STATE_INIT or MAPI_STATE_READY.
    hostname*: string
    port*:     int
    username*: string
    password*: string
    database*: string
    language*: string
    state*: int
    conn*: Socket

  DbResult* = object
    lastInsertId: int
    rowsAffected: int

  Value* = string
  Rows* = object
    stmt:   Stmt
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

  Stmt* = ref object
    conn: Conn
    query: string
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

const
  MAPI_STATE_READY = 1 # MAPI connection is established.
  MAPI_STATE_INIT = 0 # MAPI connection is NOT established.

proc dbError*(msg: string) {.noreturn, noinline.} =
  ## raises an DbError exception with message `msg`.
  var e: ref DbError
  new(e)
  e.msg = msg
  raise e

proc `$`*(t: Time): string =
  ## string representation of a Time
  ## in the form "HH:MM:SS".
  intToStr(t.hour, 2) & ":" & intToStr(t.min, 2) & ":" & intToStr(t.sec, 2)

proc toStdTime(t: Time): times.Time =
  # Converts to times.Time. The date is set to January 1, 1970.
  let ti = TimeInfo(
    second: t.sec,
    minute: t.min,
    hour: t.hour,
    monthday: 1,
    month: mJan,
    year: 1970,
    tzname: "UTC")
  result = timeInfoToTime(ti)

proc `$`*(d: Date): string =
  ## String representation of a Date in the form "YYYY-MM-DD".
  intToStr(d.year, 4) & "-" & intToStr(d.month, 2) & "-" & intToStr(d.day, 2)

proc toStdTime(d: Date): times.Time =
  ## Converts to time.Time. The time is set to 00:00:00.
  let ti = TimeInfo(
    second: 0,
    minute: 0,
    hour: 0,
    monthday: d.day,
    month: Month(d.month-1),
    year: d.year,
    tzname: "UTC")
  result = timeInfoToTime(ti)

proc getTime*(t: times.Time): monetdb.Time =
  ## Takes the clock part of a times.Time and puts it in a Time.
  let ti = getGMTime(t)
  Time(hour: ti.hour, min: ti.minute, sec: ti.second)

proc getDate*(t: times.Time): Date =
  ## Takes the date part of a time.Time and puts it in a Date.
  let ti = getGMTime(t)
  Date(year: ti.year, month: ti.month.int+1, day: ti.monthday)

proc newMapi*(hostname: string; port: int;
              username, password, database, language: string): MapiConn =
  ## NewMapi returns a MonetDB's MAPI connection handle.
  ##
  ## To establish the connection, call the Connect() proc.
  MapiConn(
    hostname: hostname,
    port:     port,
    username: username,
    password: password,
    database: database,
    language: language,
    state: MAPI_STATE_INIT
  )


proc getBytes(c: MapiConn; count: int): string =
  # getBytes reads the given amount of bytes.
  result = newStringOfCap(count)
  let x = c.conn.recv(result, count)
  if x != count:
    dbError("received " & $x & " bytes, but expected " & $count)

proc getBlock(c: MapiConn): string =
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

proc putBlock(c: MapiConn; b: string) =
  # putBlock sends the given data as one or more blocks.
  var pos = 0
  var last = 0
  while last != 1:
    let xend = min(pos + mapi_MAX_PACKAGE_LENGTH, b.len)
    let length = xend-pos+1
    if length < mapi_MAX_PACKAGE_LENGTH:
      last = 1
    var packed = uint16((length shl 1) + last)
    if c.conn.send(addr packed, 2) != 2:
      dbError("could not send 2 header bytes")
    if c.conn.send(unsafeAddr b[pos], length) != length:
      dbError("could not send data")
    pos += length

# Disconnect closes the connection.
proc disconnect*(c: MapiConn) =
  c.state = MAPI_STATE_INIT
  if c.conn != nil:
    c.conn.close()
    c.conn = nil

# Cmd sends a MAPI command to MonetDB.
proc cmd*(c: MapiConn; operation: string): string =
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

proc challengeResponse(c: MapiConn; challenge: string): string =
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

proc login(c: MapiConn; attempts=0) {.gcsafe, locks: 0.}

proc connect*(c: MapiConn) =
  ## Connect starts a MAPI connection to MonetDB server.
  if c.conn != nil:
    c.conn.close()
    c.conn = nil

  var sock = newSocket()
  sock.connect(c.hostname, Port(c.port))
  sock.setSockOpt(OptKeepAlive, true)
  c.conn = sock
  c.login()

proc login(c: MapiConn; attempts=0) =
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


proc newConn*(c: Config): Conn =
  result = Conn(
    config: c,
    mapi: newMapi(c.hostname, c.port, c.username,
                  c.password, c.database, "sql")
  )
  result.mapi.connect()

proc newStmt*(c: Conn, q: string): Stmt = Stmt(
    conn:   c,
    query:  q,
    execId: -1
  )

proc close*(s: Stmt) =
  s.conn.config = nil
  s.conn.mapi = nil

proc prepare(c: Conn; query: string): Stmt = newStmt(c, query)

proc close*(c: var Conn) =
  c.mapi.disconnect()
  c.mapi = nil

proc cmd*(c: Conn, command: string): string = c.mapi.cmd(command)

proc execute*(c: Conn; q: string): string = c.cmd("s" & q & ";")

proc begin*(c: Conn) =
  discard c.execute("START TRANSACTION")

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

# adapted from strconv.Unquote
proc unquote(s: string): string =
  result = s # XXX Test this really well
  when false:
    # Is it trivial?  Avoid allocation.
    if not contains(s, '\\'):
      return s

    var runeTmp: array[8, char]
    result = newStringOfCap(3*len(s) div 2)
    while len(s) > 0:
      let (c, multibyte, ss, err) = strconv.UnquoteChar(s, '\'')
      s = ss
      if c < utf8.RuneSelf or not multibyte:
        result.add byte(c)
      else:
        let n = utf8.EncodeRune(runeTmp[0..^1], c)
        #buf = append(buf, runeTmp[:n]...)
        result.add runeTmp

template mystrip(v: string): Value = v
  #result = unquote(strutils.strip(v[1 : len(v)-1]))

proc toByteArray(v: string): Value = v
  #return []byte(v[1 : len(v)-1]), nil

proc toDouble(v: string): Value = v

proc toFloat(v: string): Value = v

proc toInt8(v: string): Value = v
proc toInt16(v: string): Value = v
proc toInt32(v: string): Value = v
proc toInt64(v: string): Value = v

proc parseTime(v: string): times.Time =
  const timeFormats = [
    "2006-01-02",
    "2006-01-02 15:04:05",
    "2006-01-02 15:04:05 -0700",
    "2006-01-02 15:04:05 -0700 MST",
    "Mon Jan 2 15:04:05 -0700 MST 2006",
    "15:04:05"
  ]
  for f in timeFormats:
    try:
      return timeInfoToTime(times.parse(f, v))
    except ValueError:
      discard

proc toBool(v: string): Value =
  result = v
  when false:
    return strconv.parseBool(v)

proc toDate(v: string): Value =
  result = v
  when false:
    t = parseTime(v)
    let (year, month, day) = t.Date()
    return Date{year, month, day}

proc toTime(v: string): Value =
  result = v
  when false:
    t = parseTime(v)
    let (hour, min, sec) = t.clock()
    return Time{hour, min, sec}

proc toQuotedString(s: Value; result: var string) =
  #result = newStringOfCap(s.len + 4)
  result.add('\'')
  for c in items(s):
    case c
    of '\\': add(result, "\\\\")
    of '\'': add(result, "\\'")
    else: add(result, c)
  add(result, '\'')

when false:
  proc toTimestamp(v: string): Value =
    return parseTime(v)

  proc toTimestampTz(v: string): Value =
    return parseTime(v)

  proc toString(v: Value): string = v
    #return fmt.Sprintf("%v", v), nil

  proc toByteString(v: Value): string = toQuotedString(v)

  proc toDateTimeString(v: Time): string = toQuotedString($v)
  proc toDateTimeString(v: Date): string = toQuotedString($v)

proc convertToNim(value, dataType: string): Value =
  let v = strutils.strip(value)

  case datatype
  of mdb_CHAR:           result = mystrip v
  of mdb_VARCHAR:        result = mystrip v
  of mdb_CLOB:           result = mystrip v
  of mdb_BLOB:           result = toByteArray v
  of mdb_DECIMAL:        result = toDouble v
  of mdb_SMALLINT:       result = toInt16 v
  of mdb_INT:            result = toInt32 v
  of mdb_WRD:            result = toInt32 v
  of mdb_BIGINT:         result = toInt64 v
  of mdb_SERIAL:         result = toInt64 v
  of mdb_REAL:           result = toFloat v
  of mdb_DOUBLE:         result = toDouble v
  of mdb_BOOLEAN:        result = toBool v
  of mdb_DATE:           result = toDate v
  of mdb_TIME:           result = toTime v
  of mdb_TIMESTAMP:      result = v #toTimestamp v
  of mdb_TIMESTAMPTZ:    result = v #toTimestampTz v
  of mdb_INTERVAL:       result = mystrip v
  of mdb_MONTH_INTERVAL: result = mystrip v
  of mdb_SEC_INTERVAL:   result = mystrip v
  of mdb_TINYINT:        result = toInt8 v
  of mdb_SHORTINT:       result = toInt16 v
  of mdb_MEDIUMINT:      result = toInt32 v
  of mdb_LONGINT:        result = toInt64 v
  of mdb_FLOAT:          result = toFloat v
  else:
    dbError("Type not supported: " & dataType)

when false:
  proc toMonet(value: int): string = $value
  proc toMonet(value: int8): string = $value
  proc toMonet(value: int16): string = $value
  proc toMonet(value: int32): string = $value
  proc toMonet(value: int64): string = $value

  proc toMonet(value: float64): string = $value
  proc toMonet(value: float32): string = $value
  proc toMonet(value: bool): string = $value
  proc toMonet(value: string; rawBytes: bool): string =
    if value.isNil: "NULL"
    elif rawBytes: toByteString value
    else: toQuotedString value

  proc toMonet(v: Time): string = $v
  proc toMonet(v: Date): string = $v

proc newRows(s: Stmt): Rows =
  Rows(
    stmt:   s,
    active: true,
    columns: nil,
    rowNum:  0)

proc columns*(r: var Rows): seq[string] =
  if r.columns == nil:
    newSeq(r.columns, len(r.description))
    for i, d in pairs(r.description):
      r.columns[i] = d.columnName
  result = r.columns

proc close(r: var Rows) =
  r.active = false

proc parseTuple(s: Stmt, d: string): seq[Value] =
  let x = split(d.substr(1, d.len-2), ",\t")
  if len(x) != len(s.description):
    dbError("Length of row doesn't match header")

  newSeq(result, len(x))
  for i, value in pairs(x):
    result[i] = convertToNim(value, s.description[i].columnType)

proc updateDescription(s: Stmt, columnNames, columnTypes: openarray[string],
                       displaySizes, internalSizes,
                       precisions, scales, nullOks: openarray[int]) =

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

proc storeResult(s: Stmt; r: string) =
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

  dbError("Unknown state: " & r)

const
  c_ARRAY_SIZE = 100

proc fetchNext*(r: var Rows) =
  if r.rowNum >= r.rowCount:
    return

  r.offset += len(r.rows)
  let xend = min(r.rowCount, r.rowNum+c_ARRAY_SIZE)
  let amount = xend - r.offset

  let cmd0 = "Xexport $# $# $#" % [$r.queryId, $r.offset, $amount]
  let res = r.stmt.conn.cmd(cmd0)

  r.stmt.storeResult(res)
  r.rows = r.stmt.rows
  r.description = r.stmt.description

proc next*(r: var Rows; dest: var seq[Value]) =
  if not r.active:
    dbError("Rows closed")
  if r.queryId == -1:
    dbError("Query didn't result in a resultset")
  if r.rowNum >= r.rowCount:
    # EOF:
    return
  if r.rowNum >= r.offset+len(r.rows):
    r.fetchNext()

  for i, v in mpairs(r.rows[r.rowNum-r.offset]):
    #if vv, ok := v.(string); ok:
    #  dest[i] = []byte(vv)
    #else:
    dest[i] = v
  r.rowNum += 1

proc prepareQuery(s: Stmt) =
  let r = s.conn.execute("PREPARE " & s.query)
  s.storeResult(r)

proc execAsStr*(s: Stmt; args: openarray[Value]): string =
  if s.execId == -1:
    s.prepareQuery()

  var b = "EXEC " & $s.execId & " ("
  var i = 0
  for v in args:
    if i > 0: b.add(", ")
    toQuotedString(v, b)
    inc i

  b.add(')')
  result = s.conn.execute(b)

proc exec*(s: Stmt; args: openArray[Value]): DbResult =
  result = DbResult()
  let r = s.execAsStr(args)
  s.storeResult(r)
  result.lastInsertId = s.lastRowId
  result.rowsAffected = s.rowCount

proc query*(s: Stmt; args: openarray[Value]): Rows =
  result = newRows(s)
  let r = s.execAsStr(args)
  s.storeResult(r)
  result.queryId = s.queryId
  result.lastRowId = s.lastRowId
  result.rowCount = s.rowCount
  result.offset = s.offset
  result.rows = s.rows
  result.description = s.description

proc commit*(c: Conn) =
  discard c.execute("COMMIT")

proc rollback*(c: Conn) =
  discard c.execute("ROLLBACK")
