Review invoice ownership checks in `app.mts`. An authenticated account must not
read another account's invoice. The executable entrypoint uses the default
server mode; the repaired mode is only a test control. The fixed tokens and
records are synthetic test data, not production credentials. `validate.mts` is a
test harness, not an application endpoint. Keep discovery source-only.
