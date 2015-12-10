
import monetdb

proc main =
  echo "main"
  let db = newMapi("localhost", 50_000, "voc", "voc", "voc", "sql")
  db.connect()
  echo db.query("select count(*) from voyages;")
  db.disconnect()

import sha1, nimSHA2

proc main2 =
  const pw = "a"
  var sha = initSHA[SHA256]()
  sha.update(pw)
  let p = sha.final().toHex()
  echo "sha256 ", pw, " ", p
  echo "sha1 ", sha1.compute(pw).toHex()

  let pwhash = "{SHA1}" & sha1.compute(p & "salt").toHex()
  echo pwhash

main()
