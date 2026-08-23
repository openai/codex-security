Review invoice ownership checks in `app.py`. An authenticated account must not
read another account's invoice. The fixed tokens and records are synthetic test
data, not production credentials. `validate.py` is a test harness, not an
application endpoint. Keep discovery source-only.
