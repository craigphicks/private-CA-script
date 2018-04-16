echo "# private-CA-script" >> README.md
git init
git add README.md *.sh *.cnf
git commit -m "first commit"
git remote add origin git@github.com:craigphicks/private-CA-script.git
git push -u origin master
