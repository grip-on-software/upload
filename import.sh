#!/bin/bash
set -e

ORGANIZATION=$1
shift
DATE=$1
shift
if [ ! -z "$1" ]; then
	HOST=$1
else
	HOST="localhost"
fi

SCHEMA="/srv/schema"
IMPORTER="/srv/deploy/monetdb-import"
DIRECTORY="$HOME/upload/$ORGANIZATION/$DATE"

if [ ! -f "$DIRECTORY/dump.tar.gz" ]; then
	echo "No dump file to extract" >&2
	exit 1
fi

DB="gros_$ORGANIZATION"
cd "$IMPORTER/Scripts"

python "recreate_database.py" --force --no-table-import --no-schema --keep-jenkins -h "$HOST" -d "$DB"

if [ ! -d "$DIRECTORY/dump" ]; then
	tar --directory "$DIRECTORY" --no-same-owner --no-same-permissions -xzf "$DIRECTORY/dump.tar.gz"
fi

set +e
"./import_tables.sh" "$HOST" "$DIRECTORY/dump/gros-$DATE" "$DB"
status=$?
set -e
if [ $status -ne 0 ]; then
	echo "Failed to import all tables correctly" >&2
fi

cp "$DIRECTORY/dump/tables-documentation.json" $SCHEMA
cp "$DIRECTORY/dump/tables-schema.json" $SCHEMA

rm -rf "$DIRECTORY/dump"
exit $status
