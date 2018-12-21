#!/usr/bin/env Python3

__info__     = 'Script to parse a CSV file and create a Bitmap of the RAM'
__info_sup__ = 'First line of the file \'State, Address, Pages read, Pages failed, Progress\''
__info_sup2__= 'Others lines of the file \'Value1, Value2, Value3, Value4, Value5\''
__version__  = '1.0'
__require__  = 'Python3.5 or later + pillow'
__author__   = 'xAlphaDev'


#############################################################
#####################  IMPORT  ##############################
#############################################################
import argparse
import csv
import datetime
import os
import sys

from math import ceil
from PIL import Image


#############################################################
#####################  GLOBAL  ##############################
#############################################################
BACK_VALUE	= 9
END_VALUE   = -99
ACTION 		= {'print':'PRINT ', 'export':'EXPORT'}

BYE_S 					= '\n# Bye! See you soon :)'
ERROR_INT_s 			= '>>> Bad option.. I repeat, enter a good option !'
QUESTION_INPUT_s 		= '\n# What would you like to do? '
QUESTION_INTERVAL_MIN_s = '\n# Start printing from the line ? '
QUESTION_INTERVAL_MAX_s = '\n# End printing at the line ? '
WAIT_s 					= '\n# Press Enter to continue...'

LIST_COLOR = {
	0:'Black',
	1:'Blue',
	2:'Green',
	3:'Grey',
	4:'Orange',
	5:'Red',
	6:'Write',
	7:'Yellow'
}

COLOR = {
	'Black': 	(0,0,0),
	'Blue': 	(0,0,255),
	'Green': 	(0,255,0),
	'Grey': 	(182,182,182),
	'Orange': 	(255,110,0),
	'Red': 		(255,0,0),
	'Write': 	(255,255,255),
	'Yellow': 	(255,255,0)
}

SIZE_X_FILE 	= 2000
SIZE_X_FILE_MAX = 5000
SIZE_INTERVAL 	= 50
SIZE_FILE 		= 1 # Set main
COLOR_PIXEL_OK  = LIST_COLOR[2]
COLOR_PIXEL_KO  = LIST_COLOR[4]


#############################################################
##################  PROGRAM'S FUNCTIONS  ####################
#############################################################
def check_program():
	'''
	Check and parse arguments of program
	Args:
		/
	Returns:
		Args: Arguments of program
	'''
	# Info
	parser = argparse.ArgumentParser(
		description = '{0} ----------------- {1}  {2}'.format(__info__, __info_sup__,__info_sup2__)
	)
	# Version
	parser.add_argument(
		'--version', 
		action='version', 
		version='%(prog)s --> Version {0} Create by {1} // Require {2}'.format(__version__,__author__,__require__)
	)
	# File
	parser.add_argument(
		'file',
		help = 'File to parse',
		type = str
	)
	# Size X
	parser.add_argument(
		'-sX', '--size_x',
		help = 'Size X for the Bitmap to create (Default = ' + str(SIZE_X_FILE) + ')',
		type = int,
		default = SIZE_X_FILE
	)
	args = parser.parse_args()
	if(args.size_x and args.size_x not in [i for i in range(1, SIZE_X_FILE_MAX + 1)]):
		parser.error('Size X of the Bitmap must be between 1 and 5000...')
	return args


def check_file_exists(filename:str):
	'''
	Check if the file exists
	Args:
		filename: name of the file to check
	Returns:
		bool: True if the file exist or False otherwise
	'''
	return os.path.exists(filename)


def check_file_extension(filename:str):
	'''
	Check if the file is a CSV file
	Args:
		filename: name of the file to check
	Returns:
		bool: True if the file is a CSV file or False otherwise
	'''
	filename, file_extension = os.path.splitext(filename)
	return (file_extension == '.csv')


#############################################################
##########################  MENU  ###########################
#############################################################
def exec_menu(choices_menu:list, question:str):
	'''
	Select a good choice from the user
	Args:
		choices_menu: a list of the good values
		question: string for the input
	Returns:
		menu_input: int in the list 'choices_menu'
	'''
	choices_menu_str = []
	for choice in choices_menu:
		choices_menu_str.append(str(choice))
	try:
		menu_input = input(question).lower()
		while(menu_input not in choices_menu_str):
			print(ERROR_INT_s)
			menu_input = input(question).lower()
		return int(menu_input)

	except KeyboardInterrupt:
		print(BYE_S)
		sys.exit(0)


def display_main_menu(tab_full_name:list, tab_full_data:list):
	'''
	Print the Main Menu to interact with the user
	Get his choise
	Execute his requests
	Args:
		tab_full_name: tab with names of column
		tab_full_data: tab contains all the data
	Returns:
		return value
	'''
	# Init menu and values
	main_menu_s = 	'\n#####################################\n'\
					'##########  ~ MAIN MENU ~  ##########\n'\
					'#####################################\n'\
					'\n# Please enter a number for what you want to do.\n'\
					'\t>> 1. Print your data.\n'\
					'\t>> 2. Export column.\n'\
					'\t>> 3. Create Bitmap.\n'\
					'\t>> 9. Quit.\n'
	main_menu_choices 	= 	[1,2,3,9]
	
	# Display menu and get choice
	os.system('clear')
	print(main_menu_s)
	main_menu_input = exec_menu(main_menu_choices, QUESTION_INPUT_s)
	# Print data
	if(main_menu_input == main_menu_choices[0]):
		return display_print_export_menu(tab_full_name, tab_full_data, ACTION['print'])
	# Export Data
	elif(main_menu_input == main_menu_choices[1]):
		return display_print_export_menu(tab_full_name, tab_full_data, ACTION['export'])
	# Create Bitmap
	elif(main_menu_input == main_menu_choices[2]):
		return display_graphe_menu(tab_full_name, tab_full_data)
	return END_VALUE


def display_print_export_menu(tab_full_name:list, tab_full_data:list, action:str):
	'''
	Print a second menu to interact with the user to print or export file parsed
	Args:
		tab_full_name: tab with names of column
		tab_full_data: tab contains all the data
		action: print or export
	Returns:
		return value
	'''
	# Init menu and values
	print_export_menu_s = 	'\n######################################\n'\
							'##########  ~ ' + action + ' MENU ~  #########\n'\
							'######################################\n'\
							'\n# Please enter a number for what you want to ' + action + '.\n'
	for i, name in enumerate(tab_full_name):
		print_export_menu_s += '\t>> ' + str(i) + '. ' + action + ' column \'' + name + '\'\n'
	print_export_menu_s += '\t>> 9. Back.\n'
	print_export_menu_choices = [i for i in range(0, len(tab_full_name))]
	print_export_menu_choices.append(9)

	# Display menu and get choice
	os.system('clear')
	print(print_export_menu_s)
	print_export_menu_input = exec_menu(print_export_menu_choices, QUESTION_INPUT_s)
	# Back
	if(print_export_menu_input == 9):
		return BACK_VALUE
	else:
		# Third menu
		interval_menu_input,interval_min, interval_max = display_menu_interval(tab_full_data)
		# Back
		if(interval_menu_input == 9):
			return BACK_VALUE
		# Act on all data
		elif(interval_min == None and interval_max == None):
			print('\n# You have selected \'' + action + ' all data\' for the column \'' + tab_full_name[print_export_menu_input] + '\'')
			input(WAIT_s)
			if(action == ACTION['print']):
				print_column_file_parsed(tab_full_data, tab_full_name[print_export_menu_input])
			elif(action == ACTION['export']):
				export_column_file_parsed(tab_full_data, tab_full_name[print_export_menu_input])
			input(WAIT_s)
			return BACK_VALUE
		# Act on interval
		else:
			# Check min < max
			if(interval_min > interval_max):
				interval_min, interval_max = interval_max, interval_min
			print('\n# You have selected \'' + action + ' interval data\' for the column \'' + tab_full_name[print_export_menu_input] + '\'')
			print('\t>>> Min = ' + str(interval_min) + '   ///   Max = ' + str(interval_max))
			input(WAIT_s)
			if(action == ACTION['print']):
				print_column_interval_file_parsed(tab_full_data, tab_full_name[print_export_menu_input], interval_min, interval_max)
			elif(action == ACTION['export']):
				export_column_interval_file_parsed(tab_full_data, tab_full_name[print_export_menu_input], interval_min, interval_max)
			input(WAIT_s)
			return BACK_VALUE
	return END_VALUE


def display_menu_interval(tab_full_data:list):
	'''
	Print a third menu to interact with the user to select dimensions of values (print or export)
	Args:
		tab_full_data: tab contains all the data
	Returns:
		interval selected by user
	'''
	# Init menu and values
	interval_menu_s = 	'\n#####################################\n'\
						'########  ~ INTERVAL MENU ~  ########\n'\
						'#####################################\n'\
						'\n# Please enter a number for what you want to select.\n'\
						'\t>> 1. Act on all data.\n'\
						'\t>> 2. Select a minimum line and a maximum line.\n'\
						'\t>> 9. Back to main menu.\n'
	interval_menu_choices = [1,2,9]
	
	# Display menu and get choice
	os.system('clear')
	print(interval_menu_s)
	interval_menu_input = exec_menu(interval_menu_choices, QUESTION_INPUT_s)
	# Back
	if(interval_menu_input == 9):
		return interval_menu_input, None, None
	# Act on all data
	if(interval_menu_input == interval_menu_choices[0]):
		return interval_menu_input, None, None
	# Get interval
	else:
		min_value = 0
		max_value = SIZE_FILE
		interval_choices = [i for i in range (min_value, max_value)]
		interval_min = exec_menu(interval_choices, QUESTION_INTERVAL_MIN_s + '(Between ' + str(min_value) + ' and ' + str(max_value) + ') ')
		interval_max = exec_menu(interval_choices, QUESTION_INTERVAL_MAX_s + '(Between ' + str(min_value) + ' and ' + str(max_value) + ') ')
		if(abs(interval_max - interval_min) < SIZE_INTERVAL):
			print('\n>>> Interval must be > ' + str(SIZE_INTERVAL) + '. Program set a correct max value...')
			interval_max += SIZE_INTERVAL - abs(interval_max - interval_min)
		return interval_menu_input, interval_min, interval_max


def display_graphe_menu(tab_full_name:list, tab_full_data:list):
	'''
	Print a second menu to interact with the user to create a bitmap
	Args:
		tab_full_name: tab with names of column
		tab_full_data: tab contains all the data
	Returns:
		return value
	'''
	# Init menu and values
	global SIZE_X_FILE
	graph_menu_s = 	'\n#####################################\n'\
					'##########  ~ GRAPH MENU ~  #########\n'\
					'#####################################\n'\
					'\n# Please enter a number for what you want to select.\n'\
					'\t>> 1. Select color of pixels.\n'\
					'\t>> 2. Select sixe X of Bitmap (Actual => \'' + str(SIZE_X_FILE) + '\').\n'\
					'\t>> 3. Create Bitmap.\n'\
					'\t>> 9. Back to main menu.\n'
	graph_menu_choices = [1,2,3,9]
	
	# Display menu and get choice
	os.system('clear')
	print(graph_menu_s)
	graph_menu_input = exec_menu(graph_menu_choices, QUESTION_INPUT_s)
	# Back
	if(graph_menu_input == 9):
		return BACK_VALUE
	# Set color
	elif(graph_menu_input == graph_menu_choices[0]):
		return display_graphe_color_menu()
	# Set size
	elif(graph_menu_input == graph_menu_choices[1]):
		size_menu_choices = [i for i in range(1,SIZE_X_FILE_MAX + 1)]
		size_menu_input = exec_menu(size_menu_choices, QUESTION_INPUT_s + '(Between ' + str(1) + ' and ' + str(SIZE_X_FILE_MAX) + ') ')
		SIZE_X_FILE = size_menu_input
		return BACK_VALUE
	# Create Bitmap
	elif(graph_menu_input == graph_menu_choices[2]):
		# Third menu
		interval_menu_input, interval_min, interval_max = display_menu_interval(tab_full_data)
		# Back
		if(interval_menu_input == 9):
			return BACK_VALUE
		# Act on all data
		if(interval_min == None and interval_max == None):
			print('\n# You have selected the creation of the Bitmap for \'all data\'')
			input(WAIT_s)
			create_graphe(tab_full_name, tab_full_data)
			input(WAIT_s)
			return BACK_VALUE
		# Act on interval
		else:
			# Check min < max
			if(interval_min > interval_max):
				interval_min, interval_max = interval_max, interval_min
			print('\n# You have selected the creation of the Bitmap for \'interval data\'')
			print('\t>>> Min = ' + str(interval_min) + '   ///   Max = ' + str(interval_max))
			input(WAIT_s)
			create_interval_graphe(tab_full_name, tab_full_data, interval_min, interval_max)
			input(WAIT_s)
			return BACK_VALUE
	return END_VALUE


def display_graphe_color_menu():
	'''
	Print a third menu to interact with the user to select changement for the bitmap
	Args:
		/
	Returns:
		return value
	'''
	# Init menu and values
	graph_color_menu_s = 	'\n#####################################\n'\
							'##########  ~ COLOR MENU ~  #########\n'\
							'#####################################\n'\
							'\n# Please enter a number for what you want to select.\n'\
							'\t>> 1. Change color for pixel OK (Actual => \'' + COLOR_PIXEL_OK + '\').\n'\
							'\t>> 2. Change color for pixel KO (Actual => \'' + COLOR_PIXEL_KO + '\').\n'\
							'\t>> 9. Back to main menu.\n'
	graph_color_menu_choices = [1,2,9]

	# Display menu and get choice
	os.system('clear')
	print(graph_color_menu_s)
	graph_color_menu_input = exec_menu(graph_color_menu_choices, QUESTION_INPUT_s)
	# Back
	if(graph_color_menu_input == 9):
		return BACK_VALUE
	# Change color of pixel OK
	elif(graph_color_menu_input == graph_color_menu_choices[0]):
		return display_color_menu('OK')
	# Change color of pixel KO
	elif(graph_color_menu_input == graph_color_menu_choices[1]):
		return display_color_menu('KO')
	return END_VALUE


def display_color_menu(pixel:str):
	'''
	Print a fourth menu to interact with the user to select color for the pixel
	Args:
		pixel: OK or KO
	Returns:
		return value
	'''
	# Init menu and values
	color_menu_s = 	'\n#####################################\n'\
					'##########  ~ COLOR MENU ~  #########\n'\
					'#####################################\n'\
					'\n# Please enter a number for what you want to select.\n'
	for i in LIST_COLOR:
		color_menu_s += '\t>> ' + str(i) + '. Use \'' + LIST_COLOR[i] + '\'\n'
	color_menu_s += '\t>> 9. Back to main menu..\n'
	color_menu_choices = [i for i in range(0, len(COLOR))]
	color_menu_choices.append(9)

	# Display menu and get choice
	os.system('clear')
	print(color_menu_s)
	color_menu_input = exec_menu(color_menu_choices, QUESTION_INPUT_s)
	# Back
	if(color_menu_input == 9):
		return BACK_VALUE
	# Set color
	else:
		if(pixel == 'OK'):
			print('\n# You have selected the color \'' + LIST_COLOR[color_menu_input] + '\' for \'OK\'')
			global COLOR_PIXEL_OK
			COLOR_PIXEL_OK = LIST_COLOR[color_menu_input]
		elif(pixel == 'KO'):
			print('\n# You have selected the color \'' + LIST_COLOR[color_menu_input] + '\' for \'KO\'')
			global COLOR_PIXEL_KO
			COLOR_PIXEL_KO = LIST_COLOR[color_menu_input]
		input(WAIT_s)
	return BACK_VALUE


#############################################################
##########################  PARSE  ##########################
#############################################################
def parse_file(filename:str, o_tab_full_name:list, o_tab_full_data:list):
	'''
	Parse file in a list like that =>
	[
		{name1:value1,name2:value2,name3:value3,name4:value4,name5:value5},
		{name1:value1,name2:value2,name3:value3,name4:value4,name5:value5},
		{name1:value1,name2:value2,name3:value3,name4:value4,name5:value5},
		....
	]
	Args:
		filename: name of the file to parse
		o_tab_full_name: tab will be contain the name of column
		o_tab_full_data: tab will be contain all the data
	Returns:
		/
	'''
	print('>>> Beginning of the parse...')

	# Open CSV File
	file_id  = open(filename, 'r', encoding='utf-8')
	c_reader = csv.reader(file_id)

	# Parse the file in dict
	nb_field = 0
	for i, row in enumerate(c_reader):
		tmp_dict = dict()
		tmp_value = []
		if(i == 0):
			# Get name of the fields on the first line
			for field in row:
				o_tab_full_name.append(field.replace(' ', ''))
				nb_field += 1
		else:
			# Build dict with name:value
			for field in row:
				tmp_value.append(field)

			for i in range(0, nb_field):
				tmp_dict[o_tab_full_name[i]] = tmp_value[i]

			# Add to the full data
			o_tab_full_data.append(tmp_dict)

	file_id.close()
	print('>>> File parsed :)')
	return

def cut_data(tab_full_data:list, line_min:int, line_max:int):
	'''
	Cut data for the line between 'line_min' and 'line_max'
	Args:
		tab_full_data: tab contains all the data
		line_min: num of the line for start cutting
		line_max: num of the line for end cutting
	Returns:
		tab_interval_data
	'''
	tab_interval_data = []
	for i, field in enumerate(tab_full_data):
		if(i > line_max):
			return tab_interval_data
		if(i in range(line_min, line_max)):
			tab_interval_data.append(field)
	return tab_interval_data


def print_column_file_parsed(tab_full_data:list, name_column:str):
	'''
	Print the column 'name_column' of the file parsed
	Args:
		tab_full_data: tab contains all the data
		name_column: name of the column to print
	Returns:
		/
	'''
	print('\n>>> Print column ' + name_column + '...')
	for field in tab_full_data:
		try:
			print(field[name_column])
		except KeyboardInterrupt:
			pass
	return


def print_column_interval_file_parsed(tab_full_data:list, name_column:str, line_min:int, line_max:int):
	'''
	Print the column 'name_column' of the file parsed for the line between 'line_min' and 'line_max'
	Args:
		tab_full_data: tab contains all the data
		name_column: name of the column to print
		line_min: num of the line for start printing
		line_max: num of the line for end printing
	Returns:
		/
	'''
	tab_interval_data = cut_data(tab_full_data, line_min, line_max)
	return print_column_file_parsed(tab_interval_data, name_column)


def export_column_file_parsed(tab_full_data:list, name_column:str):
	'''
	Export the column 'name_column' of the file parsed in a new file.
	Name of the file: date+name_column.csv => aaaa_mm_jj-hh_mm_ss-name_column.csv
	Args:
		ttab_full_data: tab contains all the data
		name_column: column to print
	Returns:
		/
	'''
	print('\n>>> Export column ' + name_column + '...')
	# Set filename
	date 	 = str(datetime.datetime.now())[:-7]
	filename = date.replace('-','_').replace(':','_').replace(' ','-') + '-' + name_column + '.csv'
	print('\t>>> Result in the file ' + filename + '...')

	# Open file
	file_id = open(filename,'w')
	file_id.write(name_column + '\n')
	for field in tab_full_data:
		try:
			file_id.write(field[name_column] + '\n')
		except KeyboardInterrupt:
			pass
	file_id.close()
	return


def export_column_interval_file_parsed(tab_full_data:list, name_column:str, line_min:int, line_max:int):
	'''
	Export the column 'name_column' of the file parsed for the line between 'line_min' and 'line_max'
	Args:
		tab_full_data: tab contains all the data
		name_column: name of the column to print
		line_min: num of the line for start printing
		line_max: num of the line for end printing
	Returns:
		/
	'''
	tab_interval_data = cut_data(tab_full_data, line_min, line_max)
	return export_column_file_parsed(tab_interval_data, name_column)


#############################################################
##########################  GRAPH  ##########################
#############################################################
def create_graphe(tab_full_name:list, tab_full_data:list):
	'''
	Create a bitmap with the column State and Address
	Args:
		tab_full_name: tab with names of column
		tab_full_data: tab contains all the data
	Returns:
		/
	'''
	print('\n>>> Create Bitmap...\n')
	date 	 = str(datetime.datetime.now())[:-7]
	filename = date.replace('-','_').replace(':','_').replace(' ','-') + '-Bitmap.png'
	
	data_X      = []
	data_Y      = []
	y           = -1

	# Get values
	for item in tab_full_data:
		# Convert hex address to numero of page (start at 0)
		data_X.append( int(int(item[tab_full_name[1]], 0)/4096) - int(int(tab_full_data[0][tab_full_name[1]],0)/4096))
		# Convert OK or KO in 1 or 0
		data_Y.append(1 if(item[tab_full_name[0]]=='OK') else 0)

	len_data_x = len(data_X)
	# Init image
	image_size_x = (len_data_x if(SIZE_X_FILE > len_data_x) else SIZE_X_FILE)
	image_size_y = ceil(len_data_x/image_size_x) # round int up 
	image = Image.new('RGB', (image_size_x,image_size_y))
	# For each value
	for i in range(0, len_data_x):
		a = data_X[i]
		b = data_Y[i]
		# New line 
		if(a%image_size_x == 0):
			y = y + 1
		# Select color
		if(b==1):
			image.putpixel((a%image_size_x,y), COLOR[COLOR_PIXEL_OK])
		else:
			image.putpixel((a%image_size_x,y),COLOR[COLOR_PIXEL_KO])
		progress = int(i*100 / len_data_x + 1)
		output   = '\rProgress >> ' + str(progress) +'%'
		sys.stdout.write(output)
		sys.stdout.flush()
	
	# Save image
	image.save(filename, 'PNG')
	print('\n\n>>> Result in the file ' + filename + '...')
	return

def create_interval_graphe(tab_full_name:list, tab_full_data:list, line_min:int, line_max:int):
	'''
	Create a bitmap with the column State and Address for the line between 'line_min' and 'line_max'
	Args:
		tab_full_name: tab with names of column
		tab_full_data: tab contains all the data
		line_min: num of the line for start printing
		line_max: num of the line for end printing
	Returns:
		/
	'''
	tab_interval_data = cut_data(tab_full_data, line_min, line_max)
	return create_graphe(tab_full_name, tab_interval_data)

#############################################################
#####################  MAIN FUNCTION  #######################
#############################################################
def main():

	# Check program
	args_prog = check_program()
	if(not args_prog.file):
		return -1

	if(args_prog.size_x):
		global SIZE_X_FILE
		SIZE_X_FILE = args_prog.size_x

	filename = args_prog.file

	os.system('clear')
	print_intro_s = '\n##########################################################\n'\
					'##########  ~ Welcome to this File\'s Parser! ~  ##########\n'\
					'#################  ~ By ' + __author__ + ' ~  #####################\n'\
					'##########################################################\n'
	print(print_intro_s)

	if(not check_file_exists(filename) or not check_file_extension(filename)):
		print('FileNotFoundError: The file \'' + filename + '\' doesn\'t exist or is not a CSV file!!! Try again..')
		return -1

	# File correct
	full_path   = os.getcwd()
	print('>>> File \'' + filename + '\' exists (' + full_path + ')')

	# Parse file
	list_title  = []
	list_values = []
	try:
		parse_file(filename, list_title, list_values)
	except KeyboardInterrupt:
		print(BYE_S)
		return END_VALUE

	global SIZE_FILE
	SIZE_FILE = len(list_values)
	
	# Wait
	input(WAIT_s)
	
	# Main Menu
	res = display_main_menu(list_title,list_values)
	
	while(res != END_VALUE):
		res = display_main_menu(list_title, list_values)
	
	print(BYE_S)
	return END_VALUE


if(__name__ == '__main__'):
   sys.exit(main())

