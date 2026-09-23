# EasyList (most popular, ~120k rules)
wget -O blocklist.txt "https://easylist.to/easylist/easylist.txt"

# Or combine multiple lists
wget -O easylist.txt "https://easylist.to/easylist/easylist.txt"
wget -o easyprivacy.txt "https://easylist.to/easylist/easyprivacy.txt"
cat easylist.txt easyprivacy.txt > blocklist.txt   
