
import db_monet, strutils

proc main =
  var db = open("localhost", "voc", "voc", "voc")

  when false:
    exec(db, sql"""

  CREATE TABLE "voc"."test" (
      "id"   INTEGER,
      "data" VARCHAR(30)
  );""", [])
  #exec(db, sql"insert into test values(?,?)", ["34", "value üäß with \\ \' \" funny \t"])
  #exec(db, sql"insert into tbl1 values(?, ?)", ["testB", "55"])
  #db.query("create table tbl1(one varchar(10), two smallint)")
  #db.query("insert into tbl1 values('hello!',10)")
  #db.query("insert into tbl1 values('goodbye', 20)")
  echo db.getValue(sql"select count(*) from voyages")
  var i = 0
  var columnInfo: DbColumns = @[]
  for r in db.instantRows(columnInfo, sql"select * from test limit 10", []):
    echo(r)
    inc i
    if i == 8: break

  echo columnInfo
  close(db)

main()
