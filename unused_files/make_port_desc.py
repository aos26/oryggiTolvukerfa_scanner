# Creates a new file with empty lines for ports without a description

# Make sure to manually delete the contents of this file first.
newfile = open('new_port_description.csv', 'w')

oldfile = open('original_port_description.csv', 'r')
f = oldfile.readline()
pd = oldfile.readline()
for i in range(0, 1024):
  if str(i) == pd.split(';')[0]:
    newfile.write(pd)
    pd = oldfile.readline()
  else:
    newfile.write(';\n')
