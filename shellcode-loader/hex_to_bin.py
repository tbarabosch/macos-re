import sys

def main(argv):

	if len(argv) != 3:
		print "Usage: hex_to_bin.py HEXSTRING OUTPUT_FILENAME"
	else:
		print "Opening file", argv[2]
		f = open(argv[2], "wb")
		tmp = argv[1].decode("hex")
		print "Writing hexstring", argv[1], "to file"
		f.write(tmp)
		f.close()
		print "All done."

if __name__ == "__main__":
	main(sys.argv)
