#!/bin/bash

# Database dump importer.
#
# Copyright 2017-2020 ICTU
# Copyright 2017-2022 Leiden University
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
else
	python "update_database.py" -h "$HOST" -d "$DB"
fi

cp "$DIRECTORY/dump/tables-documentation.json" $SCHEMA
cp "$DIRECTORY/dump/tables-schema.json" $SCHEMA

rm -rf "$DIRECTORY/dump"
exit $status
