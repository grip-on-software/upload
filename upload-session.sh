#!/bin/sh

# Start the upload service in an environment with keyring and virtualenv.
#
# Copyright 2017-2020 ICTU
# Copyright 2017-2022 Leiden University
# Copyright 2017-2024 Leon Helwerda
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

if [ -t 0 ]; then
	echo "Usage: <password source> | ./upload-session.sh" >&2
	echo "Start the upload service in a keyring and virtualenv environment" >&2
	exit 1
fi

/usr/bin/dbus-run-session -- bash -ce "eval \$(cat | gnome-keyring-daemon --unlock); /usr/local/bin/virtualenv.sh /usr/local/envs/controller gros-upload server --scgi --debug --listen 127.0.0.1 --port 8143 --pidfile /var/log/upload/upload.pid --log-path /var/log/upload --upload-path /home/upload/upload --loopback"
