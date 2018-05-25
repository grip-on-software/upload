#!/bin/bash -e

ORGANIZATION=$1
shift
DATE=$1
shift
if [ ! -z "$1" ]; then
	HOST=$1
else
	HOST="localhost"
fi

IMPORTER="/srv/deploy/monetdb-import"

PATH="$HOME/upload/$ORGANIZATION/$DATE"
DB="gros_$ORGANIZATION"

python "$IMPORTER/Scripts/recreate_database.py" --force --no-table-import --no-schema --keep-jenkins -h "$HOST"

"$IMPORTER/Scripts/import_tables.sh" "$HOST" "$PATH" "$DB"
