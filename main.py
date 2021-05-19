import datetime

import falcon
import imghdr

import jinja2
import json
import os

import subprocess
from time import sleep

from db_utils import get_student_results, get_student_results_raw, \
					increment_balance, reset_balance, reset_passwd, set_otp, \
					validate_creds, validate_dob, verify_otp


def unsecure_verify_pin(user_pin, correct_pin):

	if len(user_pin) != len(correct_pin):
		return False

	for i in range (len(user_pin)):
		if user_pin[i] == correct_pin[i]:
			sleep(0.09)
		else:
			return False

	return True


def json_encoder(obj):
	if isinstance(obj, (datetime.date, datetime.datetime)):
		return obj.isoformat()


def set_html_template(resp, status_code, template_file, template_args = None):
	resp.status = status_code
	resp.content_type = "text/html"
	resp.text = render_template(template_file, template_args)


def render_template(template_file, template_args):

	templateLoader = jinja2.FileSystemLoader(searchpath = "templates")
	templateEnv = jinja2.Environment(loader = templateLoader)
	template = templateEnv.get_template(template_file)

	# print ("template_args:", template_args)
	# print ("type template_args:", type(template_args))

	if template_args:
		return template.render(**template_args)
	else:
		return template.render()


def read_file(fname, mode = "r"):
	fp = open(fname, mode)
	data = fp.read()
	fp.close()
	return data


def get_help_response(resp, help_json):

	resp.content_type = "application/json"
	resp.status = falcon.HTTP_200
	resp.text = json.dumps(help_json)


def construct_help_json(challenge, level, hints, flag_format = "unless otherwise mentioned, the flags would look like: HACKER_SPACE{...}"):
	return {
		"challenge": challenge,
		"level": level,
		"hints": hints,
		"flag_format": flag_format
	}


def is_integer(n):

	try:
		int(n)
	except Exception as e:
		return False

	return True


def is_date(d):
	try:
		datetime.date.fromisoformat(d)
	except Exception as e:
		return False

	return True


def report_ids(msg):
    print(f"[{os.getuid()}:{os.getgid()}] => {msg}")


def demote(uid, gid):
	print (f"UID:GID => {uid}:{gid}")
	def result():
		report_ids("starting demotion")
		os.setuid(uid)
		os.setgid(gid)
		report_ids("finished demotion")
	return result


class MainPage:

	def on_get(self, req, resp):
		challenges_json = json.loads(read_file("templates/challenges.json"))
		set_html_template(resp, falcon.HTTP_200, "challenges.html", {
			"challenges": challenges_json,
			"include_header": True
		})


class IDontExist:

	def on_get(self, req, resp, challengeNumber, random):
		set_html_template(resp, falcon.HTTP_404, "404.html", {
			"include_header": True
		})
		# print (resp.text)


class IDOR:

	def get_results(self, req, resp, raw):

		# For grabbing db creds from yml config...
		chall = "ch01"

		if raw:
			response, resp.status = get_student_results_raw(req.params["roll_no"], chall)

		else:
			response, resp.status = get_student_results(req.params["roll_no"], chall)

		response = json.dumps(response, default = json_encoder)
		resp.content_type = "text/html"
		return json.loads(response)


	def on_get_idor(self, req, resp, raw = False):

		args = None

		if "roll_no" in req.params:
			args = self.get_results(req, resp, raw)
			# print (args)

			if "raw" in req.params:
				resp.content_type = "application/json"
				resp.text = json.dumps(args)
				return

		set_html_template(resp, falcon.HTTP_200, "idor/results.html", args)

	def on_get_sqli(self, req, resp):
		# Get us the results from the RAW SQL QUERY!!!
		self.on_get_idor(req, resp, raw = True)

	def on_get_idor_help(self, req, resp):

		hints = ["Did you notice the roll_no in the URL? Try to enter a roll number next to your's :)",
			"Flag #1: Can you get the flag stored as the name of one of the students?",
			"Bonus Flag: Did you checked the page source? Maybe some interesting parameter in there? Can you get us the dob of the student named 'Sameen Shaw'? (not in the usual flag format!)",
			"Bonus Challenge: Can you try entering some HTML as a roll number? Does it works?"]

		get_help_response(resp, construct_help_json("IDOR", "EASY", hints))

	def on_get_sqli_help(self, req, resp):

		hints = ["Did you notice the roll_no in the URL? This must be fed to an SQL Query. Try to inject something that makes a valid SQL statement :)",
			"Flag #1: Can you get the contents of the secret table?",
			"Flag #2: What's the version of the database? Can you also find out the database used? Mongo/Postgres/MySQL/SQLite/DNS???... (not in the usual flag format!)"]

		get_help_response(resp, construct_help_json("SQL Injection", "EASY", hints))


class DirectoryTraversal:

	def on_get(self, req, resp):
		set_html_template(resp, falcon.HTTP_200, "directory_traversal/gallery.html", {
			"ext": "jpg",
			"start": 1,
			"end": 16
		})

	def on_get_image(self, req, resp):

		if "filename" in req.params:
			resp.text = read_file(os.path.join("templates/images", req.params["filename"]), mode = "rb")
			resp.status = falcon.HTTP_200
			resp.content_type = "image/jpg"

		else:
			resp.text = json.dumps({
				"message": "image not found"
			})
			resp.status = falcon.HTTP_400
			resp.content_type = "application/json"

	def on_get_robots(self, req, resp):
		resp.text = "user-agent: LinkChecker\ndisallow:\ncrawl-delay: 1\nuser-agent: *\ndisallow: /admin"
		resp.status = falcon.HTTP_200
		resp.content_type = "text/plain"

	def on_get_priv_esc(self, req, resp):
		set_html_template(resp, falcon.HTTP_200, "privilege_escalation/admin_iframe.html")

	def on_get_help(self, req, resp):

		hints = ["Did you notice the filename in the URL? Try to enter a different filename. Maybe try to access some file in the parent directory or any other directory using '../' sequences",
			"Flag #1: The passwd file might contain some interesting bits (not in the usual flag format!)",
			"Flag #2: Process environment variables can be accessed via /proc/self/environ file as well",
			"Bonus Flag: Try reading SSH private key of the user martha and login over SSH to get the bonus flag :)"]

		get_help_response(resp, construct_help_json("Directory Traversal", "MEDIUM", hints))

	def on_get_priv_esc_help(self, req, resp):

		hints = ["Some sites disallow certain pages to be crawled by the web bots. Can you check that file for any interesting locations?",
			"Flag #1: Can you login as admin? Try reading the password from the server configuration files!",
			"Flag #2: Can you provide the flag you got after logging in as admin?"]

		get_help_response(resp, construct_help_json("Privilege Escalation", "MEDIUM/HARD", hints))


class CommandInjection:

	def on_get(self, req, resp):
		set_html_template(resp, falcon.HTTP_200, "ci/imageart.html")

	def on_post_upload(self, req, resp):

		resp.status = falcon.HTTP_400
		resp.content_type = "application/json"
		resp.text = json.dumps({
			"message": "No image supplied or something went wrong..."
		})

		form = req.get_media()

		imageart_text = "Image Art Text"
		infile = None
		outfile = None
		final_path = "/assets/images/tmp"

		for part in form:

			# print (part.name)

			if part.name == "text":
				imageart_text = part.stream.read().decode("utf-8")

			elif part.name == "file":

				infile = os.path.join("./templates/images/tmp", f"_{part.secure_filename}")
				outfile = os.path.join("./templates/images/tmp", part.secure_filename)

				# Store this body part in a file.
				with open(infile, "wb") as fp:
					print(part.stream.pipe(fp))

				if not imghdr.what(infile) in ["jpeg", "png"]:
					resp.text = json.dumps({
						"message": "Please provide an image file [png/jpeg] only"
					})
					return

				final_path = os.path.join(final_path, part.secure_filename)

		cmd = f"convert {infile} -fill yellow -gravity South -pointsize 40 -annotate +0+36 '{imageart_text}' {outfile}"
		print (cmd)

		process = subprocess.Popen(
			cmd,
			stdout = subprocess.PIPE,
			stderr = subprocess.PIPE,
			shell = True,
			# preexec_fn = demote(1010, 1010),
			# cwd = "/tmp",
			env = {
				"FLAG": "HACKER_SPACE{42dca1c3e640c57027e8b479fab65858}"
			}
		)
		out, err = process.communicate() #timeout = 2)

		# if os.WEXITSTATUS(os.system(cmd)) == 0:
		# print (out, err)
		# print ("process.returncode:", process.returncode)

		if process.returncode == 0:
			resp.status = falcon.HTTP_200
			resp.content_type = "application/json"
			resp.text = json.dumps({
				"url": final_path
			})

		"""
		except subprocess.TimeoutExpired as e:
			print (e)
		"""
		os.unlink(infile)

	def on_get_help(self, req, resp):

		hints = ["Can you try to supply some payload that adds in another shell command (Command Injection)",
			"Flag #1: Can you find the flag using command injection?",
			"Flag #2: Process environment variables might contain some juicy information :)"]

		get_help_response(resp, construct_help_json("Command Injection", "EASY/MEDIUM", hints))


class WeakPasswords:

	chall = "ch05"
	flag = "HACKER_SPACE{d6be5e49ddc0549755a67d5faa9374d7}"

	def on_get(self, req, resp):
		set_html_template(resp, falcon.HTTP_200, "weak_passwd/login.html")

	def on_post(self, req, resp):
		form_data = req.get_media()

		roll_no = None
		passwd = None

		if "roll_no" in form_data:
			roll_no = form_data["roll_no"]
		
		if "password" in form_data:
			passwd = form_data["password"]

		if not is_integer(roll_no) or not passwd:
			set_html_template(resp, falcon.HTTP_400, "weak_passwd/login.html", {
				"message": "Missing/Invalid roll_no/password",
				"color": "red"
			})

		else:
			if validate_creds(roll_no, passwd, self.chall):
				set_html_template(resp, falcon.HTTP_200, "weak_passwd/main.html", {
					"roll_no": roll_no,
					"flag": self.flag
				})

			else:
				set_html_template(resp, falcon.HTTP_400, "weak_passwd/login.html", {
					"message": "Incorrect roll_no/password",
					"color": "red"
				})

	def on_get_passwd_reset(self, req, resp):
		if "reset" in req.params and req.params["reset"] == "success":
			set_html_template(resp, falcon.HTTP_200, "weak_passwd/login.html", {
				"message": "Password successfully reset!",
				"color": "green"
			})

		else:
			self.on_get(req, resp)

	def on_post_passwd_reset(self, req, resp):
		self.chall = "ch06"
		self.flag = "HACKER_SPACE{3154c62d1ca91f6d5c2c47c25c04f42b7}"
		self.on_post(req, resp)

	def on_get_forgot(self, req, resp):
		# set_html_template(resp, falcon.HTTP_400, "weak_passwd/forgot.html")
		# def on_post_forgot(self, req, resp):
		# form_data = req.get_media()

		roll_no = None
		dob = None
		otp = None
		new_passwd = None

		if "roll_no" in req.params:
			roll_no = req.params["roll_no"]
		
		if "dob" in req.params:
			dob = req.params["dob"]

		if "otp" in req.params:
			otp = req.params["otp"]

		if "new_password" in req.params:
			new_passwd = req.params["new_password"]

		# print ("roll_no:", roll_no)
		# print ("dob:", dob)
		# print ("otp:", otp)
		# print ("new_passwd:", new_passwd)

		chall = "ch06"

		if is_integer(otp) and new_passwd:
			if is_integer(roll_no) and is_date(dob):
				if verify_otp(roll_no, otp, chall):
					if reset_passwd(roll_no, new_passwd, chall):
						raise falcon.HTTPMovedPermanently(location = "/challenges/06?reset=success")

					else:
						set_html_template(resp, falcon.HTTP_200, "weak_passwd/login.html", {
							"message": "Password reset failed! Please try again in some time...",
							"color": "red"
						})

				else:
					set_html_template(resp, falcon.HTTP_200, "weak_passwd/forgot.html", {
						"message": "Incorrect OTP"
					})

			else:
				set_html_template(resp, falcon.HTTP_200, "weak_passwd/forgot.html", {
					"message": "Missing/Invalid roll_no/dob"
				})

		else:
			if is_integer(roll_no) and is_date(dob):
				# Validate the DOB and set the OTP
				if validate_dob(roll_no, dob, "ch01") and set_otp(roll_no, chall):
					set_html_template(resp, falcon.HTTP_200, "weak_passwd/forgot.html", {
						"otp": True,
						"roll_no": roll_no,
						"dob": dob
					})

				else:
					set_html_template(resp, falcon.HTTP_200, "weak_passwd/forgot.html", {
						"message": "Invalid DOB",
						"color": "red"
					})

			elif (roll_no and not dob) or (not roll_no and dob):
				set_html_template(resp, falcon.HTTP_200, "weak_passwd/forgot.html", {
					"message": "Missing/Invalid roll_no/dob"
				})

			else:
				set_html_template(resp, falcon.HTTP_200, "weak_passwd/forgot.html")

	def on_get_help(self, req, resp):

		hints = ["Try to bruteforce the password for any student. You already know all the roll numbers from the SQLi challenge (if not, then try that lab before starting with this one) :)",
			"Flag #1: Did you found the flag after logging in as some student?"]

		get_help_response(resp, construct_help_json("Weak Passwords", "EASY/MEDIUM", hints))

	def on_get_passwd_reset_help(self, req, resp):

		hints = ["We have forgot password feature in the login form. Can you somehow leverage it? (SQLi challenge knowledge might help here - roll numbers and dob can be utilized from that lab)",
			"Flag #1: Can you reset the password of some student and login to get the flag?",
			"Bonus Challenge: Assume that you don't know the dob of anyone. Assuming that you know the year of birth to be in the range 1998-2003, can you still bruteforce the dob and then the OTP?"]

		get_help_response(resp, construct_help_json("Weak Passwords", "EASY/MEDIUM", hints))


class CouponCodeReuse:

	balance = 100
	golden_ticket = "HACKER_SPACE{Sm4r7_l33ts_kn0w_th3!r_w4ys}"

	def on_get(self, req, resp):

		if "redeem_code" in req.params and req.params["redeem_code"] == "NXT100":
			self.balance += 100

		payload = { "balance": self.balance }

		if self.balance > 5000:
			payload["golden_ticket"] = self.golden_ticket

		set_html_template(resp, falcon.HTTP_200, "coupon_code_reuse/bank_redeem.html", payload)

	def on_get_help(self, req, resp):

		hints = ["Can we reuse the same code again and again?",
			"Flag #1: Try to increase your balance and get the golden ticket! Try to automate it probably to avoid manual pain...",
			"Food for thought: Redeem code seems to be small. Have you seen some codes? Uber/Grab/some food app? Don't they look like a perfect candidate for bruteforcing? Would that attack work? Answer: It would, provided that there are no rate-limits or else you might end up loosing your account!"]

		get_help_response(resp, construct_help_json("Coupon Code Reuse", "EASY", hints))


class TimingAttacks:

	flag = "HACKER_SPACE{Purrrrf3c7_T!m!ng}"
	pin = "xptYNWNB9H"

	def on_get(self, req, resp):

		if "pin" in req.params:

			if unsecure_verify_pin(req.params["pin"], self.pin):
				set_html_template(resp, falcon.HTTP_200, "timing_attacks/secure_area.html", {
					"flag": self.flag
				})

			else:
				set_html_template(resp, falcon.HTTP_200, "timing_attacks/secure_area.html", {
					"message": "Incorrect PIN!"
				})

		else:
			set_html_template(resp, falcon.HTTP_200, "timing_attacks/secure_area.html")

	def on_get_help(self, req, resp):

		hints = ["Some applications might leak information unintentionally say via sounds a printer makes while printing a document or via RF waves or by response delays... This might end up leaking some information for the attacker to retrieve the information they are looking for... But this process can be hard and non-deterministic!",
			"Flag #1: Can you find the correct (10-digit) secure PIN? Provided that the backend checks the PIN characters sequentially and for every correct digit, it spends 0.9 seconds processing it... (not in the usual flag format)",
			"Flag #2: What's the flag retrieved after entering the secret PIN?"]

		get_help_response(resp, construct_help_json("Timing Attacks", "HARD", hints))


class DateBasedAttacks:

	def on_get(self, req, resp):
		# Embed ttyd in an iframe...
		set_html_template(resp, falcon.HTTP_200, "date_based_attacks/ttyd_iframe.html")

	def on_get_help(self, req, resp):

		hints = ["Usually applications might end up storing the install date and time in some file/registry and use that to determine if the trial period is over or not. By modifying the install date and time, the software can be used indefinitely for FREE (not ethical, just trying it for knowledge purposes, so please don't use your knowledge to do some shady stuff!)",
			"Flag #1: Can you find the file containing the date time info? Provide the full path. strace/ltrace would prove to be good friends here... (not in the usual flag format)",
			"Flag #2: Can you get past the date time checks and get the flag? Just need to make sense of the number and modify it accordingly (it's epoch)"]

		get_help_response(resp, construct_help_json("Date based Attacks", "EASY/MEDIUM", hints))


class RaceConditions:

	chall = "ch11"
	golden_ticket = "HACKER_SPACE{P4t_thys3lf_f0r_g3tt!ng_th!s_r!gh7}"

	account_id = "7218540336"
	balance = 100.0
	redeem_code_usage_quota = 1

	def on_get(self, req, resp):

		if "reset" in req.params:
			self.balance = reset_balance(self.account_id, 100, self.chall)
			self.redeem_code_usage_quota = 1
			set_html_template(resp, falcon.HTTP_200, "coupon_code_reuse/bank_redeem.html", {
				"balance": int(self.balance)
			})
			print ("balance:", self.balance)
			print ("self.redeem_code_usage_quota:", self.redeem_code_usage_quota)
			return

		print ("balance:", self.balance)
		print ("self.redeem_code_usage_quota:", self.redeem_code_usage_quota)

		payload = {}

		if "redeem_code" in req.params:

			if req.params["redeem_code"] == "INC100":

				if self.redeem_code_usage_quota != 0:
					self.balance = increment_balance(self.account_id, 100, self.chall)

					print ("BALANCE:", self.balance)
					print ("REDEEM CODE USAGE QUOTA:", self.redeem_code_usage_quota)
					sleep(1)

					self.redeem_code_usage_quota -= 1

				else:
					payload["message"] = "Redeem code can only be used once..."

			else:
				payload["message"] = "Invalid redeem code..."

		payload["balance"] = self.balance

		if self.balance > 700:
			payload["golden_ticket"] = self.golden_ticket

		set_html_template(resp, falcon.HTTP_200, "coupon_code_reuse/bank_redeem.html", payload)

	def on_get_help(self, req, resp):

		hints = ["Can we reuse the same code again and again? Maybe try sending parallel requests?",
			"Flag #1: Try to increase your balance over $700 and get the flag!",
			"Food for thought: What went wrong? What's the root of our problem? How can we try to prevent this attack?"]

		get_help_response(resp, construct_help_json("Race Conditions", "HARD", hints))



# Routes
app = falcon.App()

app.add_route("/challenges", MainPage())

app.add_static_route("/assets", os.path.join(os.getcwd(), "templates"))

idor = IDOR()
app.add_route("/challenges/01", idor, suffix = "idor")
# app.add_route("/challenges/01/results", IDOR(), suffix = "results")
app.add_route("/challenges/01/help", idor, suffix = "idor_help")


directory_traversal = DirectoryTraversal()
app.add_route("/challenges/02", directory_traversal)
app.add_route("/challenges/02/help", directory_traversal, suffix = "help")
app.add_route("/gallery", directory_traversal, suffix = "image")


app.add_route("/challenges/03", idor, suffix = "sqli")
app.add_route("/challenges/03/help", idor, suffix = "sqli_help")

command_injection = CommandInjection()
app.add_route("/challenges/04", command_injection)
app.add_route("/challenges/04/upload", command_injection, suffix = "upload")
app.add_route("/challenges/04/help", command_injection, suffix = "help")


weak_passwds = WeakPasswords()
app.add_route("/challenges/05", weak_passwds)
app.add_route("/challenges/05/help", weak_passwds, suffix = "help")

app.add_route("/challenges/06", weak_passwds, suffix = "passwd_reset")
app.add_route("/challenges/06/help", weak_passwds, suffix = "passwd_reset_help")

app.add_route("/forgot", weak_passwds, suffix = "forgot")

coupon_code_reuse = CouponCodeReuse()
app.add_route("/challenges/07", coupon_code_reuse)
app.add_route("/challenges/07/help", coupon_code_reuse, suffix = "help")

timing_attacks = TimingAttacks()
app.add_route("/challenges/08", timing_attacks)
app.add_route("/challenges/08/help", timing_attacks, suffix = "help")

date_based_attacks = DateBasedAttacks()
app.add_route("/challenges/09", date_based_attacks)
app.add_route("/challenges/09/help", date_based_attacks, suffix = "help")

app.add_route("/challenges/10", directory_traversal)
app.add_route("/challenges/10/robots.txt", directory_traversal, suffix = "robots")
app.add_route("/challenges/10/admin", directory_traversal, suffix = "priv_esc")
app.add_route("/challenges/10/help", directory_traversal, suffix = "priv_esc_help")

race_conditions = RaceConditions()
app.add_route("/challenges/11", race_conditions)
app.add_route("/challenges/11/help", race_conditions, suffix = "help")

app.add_route("/challenges/{challengeNumber}", IDontExist())
app.add_route("/challenges/{challengeNumber}/{random}", IDontExist())