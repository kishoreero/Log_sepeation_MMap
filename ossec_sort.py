import mmap
import os
import glob
import configparser
import time
from datetime import datetime
from sys import exit
from collections import Counter
import logging

logCounter=Counter()
config = configparser.ConfigParser()
config.read('ossec_sort.ini')
log = configparser.ConfigParser()
log.read('ossec_sort.run')
logSourceName=log.get('run','logSourceName')
filename=log.get('run','runlogname')

date_log=('%Y-%m-%d %H:%M:%S')
FORMAT = "%(asctime)s.%(msecs)03d :: %(levelno)s :: %(message)s"
logging.basicConfig(level=logging.INFO, format=FORMAT, datefmt=date_log, filename=filename)

logging.info("Process started")
logging.info(f"Opened file {logSourceName}")

while True:
    print("inside 1st while") 
    logInodeRef=log.get('run','loginoderef')
    logSizeRef=log.get('run','logsizeref')
    logInodeCur=os.stat(logSourceName).st_ino
    logSizeCur=os.path.getsize(logSourceName)
    with open(logSourceName, mode="r", encoding='utf8') as fileobj:
        with mmap.mmap(fileobj.fileno(), length=0, access=mmap.ACCESS_READ) as fullmap:
            if((int(logInodeRef) != int(logInodeCur))):
                log.set('run','logInodeRef',str(logInodeCur))
                log.set('run','logSizeRef',str(logSizeCur))
                with open("ossec_sort.run", "w+") as configfile:
                    log.write(configfile)
            if((int(logInodeRef) == int(logInodeCur)) and (int(logSizeCur) == int(logSizeRef))):
                logging.info("Process completed")
                break
            if((int(logInodeCur) != int(logInodeRef))):
                byte=0
                logging.warning("File changed and processing with new file")
                log.set('run','logInodeRef',str(logInodeCur))
                log.set('run','logSizeRef',str(logSizeCur))
                log.set('run','seekByte',str(byte))
                with open("ossec_sort.run", "w+") as configfile:
                    log.write(configfile)
            while True:
                print("inside 2nd while")
                seekByte=log.get('run','seekByte')
                print("inside while....about to readline. Seek:",seekByte)
                fullmap.seek(int(seekByte))
                line=fullmap.readline()
                if not line:
                    print("End of line,Inside if not line condition." )
                    logging.warning(f"End of file {logSourceName}")
                    logInodeRef=log.get('run','logInodeRef')
                    logSizeRef=log.get('run','logSizeRef')
                    logSizeCur=os.path.getsize(logSourceName)
                    logInodeCur=os.stat(logSourceName).st_ino
                    seekByte=log.get('run','seekByte')
                    print(logInodeRef,'==',logInodeCur,'    ',logSizeCur,'==',logSizeRef)
                    print(logSizeCur,'>',logSizeRef,'   ',logInodeCur,'==',logInodeRef)
                    print(logInodeCur,'!=',logInodeRef)
                    if((int(logInodeRef) == int(logInodeCur)) and (int(logSizeCur) == int(logSizeRef))):
                        print("inside if in if not line condition")
                        logging.info("Ending process")
                        print(logInodeRef,'==',logInodeCur,'    ',logSizeCur,'==',logSizeRef,)
                        break
                    elif((int(logSizeCur) > int(logSizeRef)) and (int(logInodeCur) == int(logInodeRef))):
                        logging.info("File size changed and processing with new data")
                        print("inside 1st elif in if not line")
                        print(logSizeCur,'>',logSizeRef,'   ',logInodeCur,'==',logInodeRef)
                        #seekByte=logBytesRead
                        time.sleep(15)
                        break
                    print("out of line check...")   
                    print("inside else.....distro")
                for section in config.sections():
                    matchString = config.get(section, 'match')
                    logCountString = config.get(section, 'logCountString')
                    outFileDir = config.get(section, 'outFileDir')
                    outFileName = config.get(section, 'outFileName')
                    maxLines = config.get(section, 'maxLines')
                    outFileDirFull=outFileDir+"/"+logCountString+"/"
                    print("matchString",matchString)
                    print(line)        
                    if(matchString in str(line)):
                        print("inside", matchString)
                        #print("inside matchstring")
                        outname=outFileDirFull+outFileName+".log"
                        outFile=open(outname,"a")
                        #log_outFile=str(outFile)
                        outFile.write((str(line,'utf-8')).rstrip())
                        outFile.write("\n")
                        outFile.close()
                        logCounter.update([logCountString])
                        print(type(logCounter[logCountString]), '  ', type(maxLines))
                        if(logCounter[logCountString] >= int(maxLines)):
                            date = datetime.now().strftime('%Y%m%d.%H%M%S')
                            setFileName = date+"."+outFileName+".start"
                            log_setfile=str(setFileName)
                            os.rename(outFileDirFull+outFileName+".log",outFileDirFull+"/"+setFileName)
                            logCounter[logCountString]=0
                            print(matchString,' ',outFileName,' ', maxLines,' ', logCounter[logCountString],'  ',logCounter)
                            logging.info(f"processed {outname} :: Generated {log_setfile}")
                        break  
                SeekByte=int(seekByte)
                SeekByte+=len(line)
                log.set('run','seekByte',str(SeekByte))
                log.set
                with open("ossec_sort.run", "w+") as logrunfile:
                    log.write(logrunfile)
