from sqlalchemy import create_engine, engine
from sqlalchemy import MetaData
from sqlalchemy.orm import sessionmaker

from sqlalchemy.sql import text

from crypt import crypt

import secrets
import string
import yaml


def generate_otp():
	return "".join(secrets.choice(string.digits) for _ in range(4))


def get_config(fname):

	config = {}

	with open("./db_config.yml") as fp:
		# The FullLoader parameter handles the conversion from YAML
		# scalar values to Python the dictionary format
		config = yaml.safe_load(fp)

	# print (config)
	return config


def get_db_engine(chall, config):

	return create_engine(engine.url.URL(drivername="postgresql+psycopg2",
			username = config[chall]["username"],
			password = config[chall]["password"],
			host = config["host"],
			port = config["port"],
			database = config[chall]["database"]
		)
	)


def get_session(db_engine):
	return sessionmaker(bind = db_engine)()


def get_table(db_engine, tbl):
	meta = MetaData()
	meta.reflect(bind = db_engine)
	return meta.tables[tbl]


def get_student_results(roll_no, chall):

	config = get_config("./db_config.yml")["database_info"]

	db_engine = get_db_engine(chall, config)
	session = get_session(db_engine)

	tbl = get_table(db_engine, config[chall]["table"])

	student_result = session.query(tbl).filter(
		tbl.columns.roll_no == roll_no
	).one_or_none()

	if student_result:
		return { "response": [student_result._asdict()] }, 200

	return { "error": { "message": "no students found", "roll_no": roll_no } }, 400


def get_student_results_raw(roll_no, chall):

	config = get_config("./db_config.yml")["database_info"]
	db_engine = get_db_engine(chall, config)

	student_results = []

	with db_engine.connect() as conn:
		result = conn.execute(text(f"Select * from {config[chall]['table']} where roll_no='{roll_no}'"))
		# print ("\n\nRESULT:", result.__dict__)
		for row in result:
			student_results.append(row._asdict())

	print ("student_results:", student_results)

	if len(student_results) > 0:
		return { "response": student_results }, 200

	return { "error": { "message": "not students found", "roll_no": roll_no } }, 400


def validate_creds(roll_no, passwd, chall):

	config = get_config("./db_config.yml")["database_info"]

	db_engine = get_db_engine(chall, config)
	session = get_session(db_engine)

	print ("roll_no, passwd, chall:", roll_no, passwd, chall)

	tbl = get_table(db_engine, config[chall]["table"])

	student_login = session.query(tbl).filter(
		tbl.columns.roll_no == roll_no,
		tbl.columns.passwd == crypt(passwd, "$6$DW3rMhTbdeHj/sYV")
	).one_or_none()

	print ("student_login:", student_login)

	return True if student_login else False


def validate_dob(roll_no, dob, chall):

	config = get_config("./db_config.yml")["database_info"]

	db_engine = get_db_engine(chall, config = config)
	session = get_session(db_engine)

	tbl = get_table(db_engine, config["ch01"]["table"])

	student_info = session.query(tbl).filter(
		tbl.columns.roll_no == roll_no,
		tbl.columns.dob == dob
	).one_or_none()

	return True if student_info else False


def set_otp(roll_no, chall, otp = "0000"):

	config = get_config("./db_config.yml")["database_info"]
	db_engine = get_db_engine(chall, config)

	while otp == "0000":
		otp = generate_otp()

	tbl = get_table(db_engine, config[chall]["table"])
	update_stmt = tbl.update().values(otp = otp).where(
		tbl.columns.roll_no == roll_no
	)

	try:
		with db_engine.connect() as conn:
			conn.execute(update_stmt)

		return True

	except Exception as e:
		return False


def verify_otp(roll_no, otp, chall):

	config = get_config("./db_config.yml")["database_info"]

	db_engine = get_db_engine(chall, config)
	session = get_session(db_engine)

	tbl = get_table(db_engine, config[chall]["table"])

	student_login = session.query(tbl).filter(
		tbl.columns.roll_no == roll_no,
		tbl.columns.otp == otp
	).one_or_none()

	if student_login:
		# Verified!
		# Set the OTP to None!
		set_otp(roll_no, chall, otp = None)
		return True

	else:
		return False


def reset_passwd(roll_no, new_passwd, chall):
	# Reset password!

	print ("reset_passwd(roll_no, new_passwd, chall):", roll_no, new_passwd, chall)

	config = get_config("./db_config.yml")["database_info"]

	db_engine = get_db_engine(chall, config)
	session = get_session(db_engine)

	tbl = get_table(db_engine, config[chall]["table"])

	update_stmt = tbl.update().values(
		passwd = crypt(new_passwd, "$6$DW3rMhTbdeHj/sYV")
	).where(tbl.columns.roll_no == roll_no)

	try:
		with db_engine.connect() as conn:
			conn.execute(update_stmt)

		return True

	except Exception as e:
		return False


def increment_balance(account_id, amount, chall):

	config = get_config("./db_config.yml")["database_info"]

	db_engine = get_db_engine(chall, config)
	session = get_session(db_engine)

	tbl = get_table(db_engine, config[chall]["table"])

	account_info = session.query(tbl).filter(tbl.columns.account_id == account_id).one_or_none()

	print ("ACCOUNT_INFO:", account_info._asdict())

	if not account_info:
		return 100.0

	update_stmt = tbl.update().values(
		balance = account_info.balance + amount
	).where(tbl.columns.account_id == account_id)

	try:
		with db_engine.connect() as conn:
			conn.execute(update_stmt)

	except Exception as e:
		print ("Exception...", str(e))

	account_info = session.query(tbl).filter(tbl.columns.account_id == account_id).one_or_none()

	return account_info.balance if account_info else 100.0


def reset_balance(account_id, amount, chall):

	config = get_config("./db_config.yml")["database_info"]

	db_engine = get_db_engine(chall, config)
	session = get_session(db_engine)

	tbl = get_table(db_engine, config[chall]["table"])

	update_stmt = tbl.update().values(
		balance = amount
	).where(tbl.columns.account_id == account_id)

	try:
		with db_engine.connect() as conn:
			conn.execute(update_stmt)

	except Exception as e:
		print (str(e))
	
	return amount