#!/bin/bash

PORT=9999

# Check if port is already in use and kill the process if it is
if lsof -i :$PORT > /dev/null; then
    echo "Port $PORT is already in use. Attempting to kill the process..."
    # Get the PID of the process using the port and kill it
    lsof -ti :$PORT | xargs kill -9
    echo "Process killed."
fi

echo "Starting server on port $PORT..."
./build/server $PORT 