#!/system/bin/sh

in_file="user_init.sh"
out_file="gen/user_init.c"

c_string='static const char user_init[] = "'

temp_string=""

while IFS= read -r line || [[ -n "$line" ]]; do
    escaped_line=$(echo "$line" | sed 's/\\/\\\\/g; s/"/\\"/g')
    temp_string+="$escaped_line\\n"
done <"$in_file"

c_string+="${temp_string}\";"

echo "$c_string" >$out_file

touch userd.c
