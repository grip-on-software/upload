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
DIRECTORY="$HOME/upload/$ORGANIZATION/$DATE"

if [ ! -f "$DIRECTORY/dump.tar.gz" ]; then
	echo "No dump file to extract" >&2
	exit 1
fi

DB="gros_$ORGANIZATION"

python "$IMPORTER/Scripts/recreate_database.py" --force --no-table-import --no-schema --keep-jenkins -h "$HOST" -d "$DB"

if [ ! -d "$DIRECTORY/dump" ]; then
	tar xzf --no-same-owner --no-same-permissions "$DIRECTORY/dump.tar.gz"
fi

"$IMPORTER/Scripts/import_tables.sh" "$HOST" "$DIRECTORY/dump/gros-$DATE" "$DB"

rm -rf "$DIRECTORY/dump"