# check for taint in system log files.

import os

# check a given log file for training logs
def readLogFile(log):
    try:
        print((log.split("/"))[3] + ":")

        with open(log) as logFile:

            for line in logFile:
                if "taint" in line:
                    print(line.strip("\n"))
    except:
            pass
    