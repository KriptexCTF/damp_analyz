import pyshark
import sys
import time
import os
from time import strftime, localtime
from progress.bar import IncrementalBar
import datetime
import numpy as np
import matplotlib.pyplot as plt

#Функция для активации менюшки программы
def action():
	choice = "" #Переменная хранящая выбор юсера
	while(choice.lower() != "exit"):
		menu()
		choice = input(":>> ")
		if(choice == '1'): #Вывод списка пользователей
			users(mac_arr_list)
		elif(choice == '2'): #Вывод активности пользователя
			user_activity(mac_arr)
		elif(choice == '3'): #Вывод полной информации о пользователе
			user_info()
		elif(choice == '4'): #Вывод информации о всех
			all_info()
#Принт менюшки
def menu():
	print("""
MENU
use exit to quite
1) Увидеть список пользователей
2) Время когда пользователь выходит в сеть
3) Подробная информация о пользователе
4) Подробная информация о всех""")

#Вывод списка пользователей
def users(users_arr):
	print("Users━┓")
	for i in users_arr:
		print(f"      ┣━ {i}") #Принт мак адреса
	print(f"      Total: {a}") #Итоговое количество пользователей

#Информация активности пользователя с датами и временем
def user_activity(arr):
	mac = ""
	while(mac not in mac_arr_list): #Проверка на корректность мак адреса
		if(mac == "exit"):
			action() #Вызов активной менюшки
		mac = input("Enter user mac: ")
	for i in arr: #Проходим по массиву и находим строки с нашим маком
		if(i[0] == mac):
			print("  ━ Date: " + str(i[2]) + ":00  Count: " + str(i[1]))

#Подсчет общего количество arp пакетов у пользователя
def total_user_active(mac_addr):
	q = 0
	for i in mac_arr_daily:
		if(i[0] == mac_addr):
			q += i[1]
	return q

#Функция вывода полной информации о пользователе
def user_info():
	date = date_all() #Запишем в переменную массив с существвующими датами в дампе
	mac = ""
	time_day = ["0:00 - 8:00","9:00 - 16:00","17:00 - 24:00"] #Массив с промежутками времени
	mat_ogid = 0
	dispers = 0
	total_arp = arp_count #Всего arp запросов
	while(mac not in mac_arr_list):
		if(mac == "exit"):
			action()
		mac = input("Enter user mac: ")
	qwe = total_user_active(mac)
	data_mat_ogid = 0
	data_mat_ogid_count = 1
	data_dispers = 0
	for i in range(len(date)): #Вывод дней недели и вероятность появления в этот день юзера
		for j in mac_arr:
			data_from_mac_arr = j[2].split(' ')
			if((date[i][0] == data_from_mac_arr[0]) and (mac == j[0])):
				date[i][1] += j[1]
				data_dispers += (data_mat_ogid_count ** 2) * (j[1]/qwe)
				data_mat_ogid += data_mat_ogid_count * (j[1]/qwe)
				data_mat_ogid_count += 1
	print("Date━┓")
	for i in date:
		q = i[0].split('-')
		today = datetime.datetime(int(q[0]), int(q[1]), int(q[2]))
		print(f"     ┣━ {data_dict[today.weekday()]} вероятность: {i[1]/qwe}")
	print('\n')
	m, m_count, x = 0, 0, 1
	#Вычисление вероятности, мат ожид, дисперсии и другое
	for i in time_day: 
		for j in mac_arr_daily:
			if((i == j[2]) and (mac == j[0])):
				print(i + "  Вероятность появления: " + str(j[1]/qwe))
				mat_ogid += x * (j[1]/qwe)
				dispers += (x ** 2) * (j[1]/qwe)
				m += j[1]
				m_count += 1
		x += 1
	dispers -= mat_ogid ** 2
	print("Мат. ожидание: " + str(mat_ogid))
	print("Дисперсия: " + str(dispers))	
	sredn = m/(len(date)*3)
	print("Коэфициент вариации: " + str((dispers ** 0.5)/sredn)) #Вычисление коэфициента вариации
	count = [] #Создание гистограммы
	days = []
	for i in date: #Заполнение массивов для гистограммы
		q = i[0].split('-')
		today = datetime.datetime(int(q[0]), int(q[1]), int(q[2]))
		day_name = data_dict[today.weekday()]
		count.append(i[1])
		days.append(f"{day_name}")
	#Выбор выводить или нет гистограмму
	if(input("Do want view gistigramm? [y/n] :>> ") == 'y'):
		plt.bar(days, count)
		plt.show()

#Вывод информации о всех пользователях
def all_info():
	#Пройдемся по массиву мак адресов и высчитаем вероятность появления
	for mac in mac_arr_list:
		print("\n" + mac + "━┓")
		time_day = ["0:00 - 8:00","9:00 - 16:00","17:00 - 24:00"]
		mat_ogid, dispers = 0, 0
		total_arp = arp_count
		qwe = total_user_active(mac)
		x = 1
		for i in time_day:
			for j in mac_arr_daily:
				if((i == j[2]) and (mac == j[0])):
					print("		  ┣━" + i + "  Вероятность появления: " + str(j[1]/qwe))
					mat_ogid += x * (j[1]/qwe)
					dispers += (x ** 2) * (j[1]/qwe)
			x += 1
		dispers -= mat_ogid ** 2
		print(' '*18 + "Мат. ожидание: " + str(mat_ogid))
		print(' '*18 + "Дисперсия: " + str(dispers))

#Считаем количество арп пакетов
def arp_count(array_arp, file_path):
	#Загружаем дамп в переменную cap
	cap = pyshark.FileCapture(file_path, display_filter="arp")
	cap.load_packets()
	arp_count, mac_count = 0, 0
	#Инициализация прогресс бара
	bar = IncrementalBar('Progress', max = len(cap))
	for packet in cap:
		bar.next() #Увеличение прогресса
		#Подсчет количества пакетов
		if 'ARP' in packet:
			arp_count += 1
			mac_count = find_mac(packet, mac_count)
	bar.finish() #Завершаем прогресс бар
	return arp_count

#Количество мак адресов
def mac_count_number(arr_mac_adr):
	q = 0
	for i in arr_mac_adr:
		if(i[0] not in mac_arr_list):
			mac_arr_list.append(i[0])
	return len(mac_arr_list)

#Подсчет итоговой активности пользователей по времени
def time_act(arr_mac_adr):
	q = -1
	for i in arr_mac_adr:
		if not any(i[2] in j for j in time_active):
			time_active.append([i[2], i[1]])
			q += 1
		else:
			time_active[q][1] += i[1]

#Из пакетов арп достаем мак адреса
def find_mac(packet, mac_count):
	offset = str(packet).find("Source:")
	string = ""
	time_pocket = str(packet.frame_info.time_epoch)
	while(str(packet)[offset] != '\n'):
		string += str(packet)[offset]
		offset += 1
	string = string.split(' ')
	#Заполняем массив вставляя маки дату и количество запросов
	if string[1] not in mac_arr:
		mac_arr.append([0, 1, ""])
		mac_arr[mac_count][0] = string[1]
		mac_arr[mac_count][2] = str(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(float(time_pocket))).split(':')[:-2]).replace("', '", ':').replace("['", '').replace("']", '')
		mac_count += 1
	return mac_count

#Сортируем массив, чтобы схлопнуть повторяющиеся строки и посчитать кол-во запросов
def arr_sort(mac_arr_not_sort):
	#Сортируем массив по первому и третьему столбцу
	mac_arr_not_sort.sort(key = lambda x: (x[0], x[2]), reverse=True)
	mac_sort = []
	sort_len = 0
	for i in range(len(mac_arr_not_sort)):
		if(len(mac_sort) == 0):
			mac_sort.append([0, 1, (mac_arr_not_sort[i][2])])
			mac_sort[i][0] = mac_arr_not_sort[i][0]
			sort_len = 1
		elif((mac_arr_not_sort[i][0] == mac_sort[sort_len - 1][0]) and (mac_arr_not_sort[i][2] == mac_sort[sort_len - 1][2])):
			mac_sort[sort_len - 1][1] += 1
		else:
			mac_sort.append([0, 1, (mac_arr_not_sort[i][2])])
			mac_sort[sort_len][0] = mac_arr_not_sort[i][0]
			sort_len += 1
	mac_sort.sort(key = lambda x: x[2], reverse=False)
	return mac_sort

#Красивый вывод массива на экран
def buit_print(mac_arr, result_time):
	for i in mac_arr:
		hour = int(str(str(i[2].split(' ')[-1:]).split(':')).replace('["[', '').replace(']"]', '').replace("'", "")) + 1
		if(hour == 25):
			hour = "00"
		else:
			hour = str(hour)
		print(" ┣━ " + str(i[0]) + "  Date: " + str(i[2]) + ":00-" + hour + ":00" + "  Count: " + str(i[1]))
	print(f"Total count: {len(mac_arr)}")
	print("Time execution: " + str(result_time) + " sec")

#Определение в какие рамки времени подходит выремя отправки пакета
def help_time_str(t):
	if ((t >= 0) and (t <= 8)):
		return "0:00 - 8:00"
	elif ((t >= 9) and (t <= 16)):
		return "9:00 - 16:00"
	elif ((t >= 17) and (t <= 24)):
		return "17:00 - 24:00"

#Вспомогательная функция для mac_arr_daily_time()
def find_mac_in_arr(mac_addr, arr, mac_time, b):
		for i in range(len(arr)):
			if((mac_addr in arr[i]) and (mac_time in arr[i])):
				return i
#Вычисление активности пользователя в временной рамке
def mac_arr_daily_time():
	#  0 - 8 | 9 - 16 | 17 - 24
	for i in range (len(mac_arr)):
		mac_time_not = mac_arr[i][2]
		mac_time = int((str((mac_time_not.split(' '))[-1:])).replace("['", '').replace("']", ''))
		if (any(mac_arr[i][0] in j for j in mac_arr_daily)):
			j = find_mac_in_arr(mac_arr[i][0], mac_arr_daily, help_time_str(mac_time), mac_arr[i][1])
			if(j == None):
				mac_arr_daily.append([mac_arr[i][0], mac_arr[i][1], help_time_str(mac_time)])
			else:
				mac_arr_daily[j][1] += mac_arr[i][1]
		else:
			mac_arr_daily.append([mac_arr[i][0], mac_arr[i][1], help_time_str(mac_time)]) 

#Нахождение всех дат
def date_all():
	global data_dict
	data_dict = {0:'Monday', 1:'Tuesday', 2:'Wednesday', 3:'Thursday', 4:'Friday', 5:'Saturday', 6:'Sunday'}
	date_arr = []
	for i in mac_arr:
		date = str((i[2].split(' '))[0])
		if not any(date in j for j in date_arr):
			date_arr.append([date, 0])
	return date_arr

#Начало выполнения

#Проверка на существование файла
try:
	file_path = sys.argv[1]
	if(not(os.path.isfile(file_path))):
		raise Exception
except:
	sys.exit(f"ERROR\nDump file <<{sys.argv[1]}>> not exist or filename incorected!\nUse:  python3 programm_name damp_file.pcapng")
#Объявление всех переменных
array_arp = [] 
arr_time_mac = []
mac_arr_list = []
mac_arr = []
time_active = []
mac_arr_daily = []
#Запуск таймера на выполнение программы
start_time = time.time()
arp_count = arp_count(array_arp, file_path)
#Остановка таймера
stop_time = time.time()
#Вычисление итогового времени работы
result_time = round(stop_time - start_time, 3)
print(f"Number of ARP packets: {arp_count}")
mac_arr = arr_sort(mac_arr)
buit_print(mac_arr, result_time)
time_act(mac_arr)
mac_arr_daily_time()
a = mac_count_number(mac_arr)
action()
