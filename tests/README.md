Tests
=====

Tests must be run on a postgresql instance, with the `pg_trgm` extension enabled:

```sql
CREATE EXTENSION IF NOT EXISTS pg_trgm;
```

First you have to change the `database_uri` value in the `./tests/opencve.cfg` file:

```
database_uri = postgresql://user:secret@localhost:5432/opencve_tests
```

Then the tests can be executed with the following commands:

```
(venv) pip install pytest
(venv) pytest tests/
```
