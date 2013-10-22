#!/bin/bash
grep "===" out.trace > classes.sd
echo "" >> classes.sd
grep -v "===" out.trace >> classes.sd
sed -i "s/\./\\\./g" classes.sd
sed -i "s/\[/\(/g;s/\]/\)/g" classes.sd
sed -i "s/===/\[a\]/g" classes.sd
sed -i "s/---/\./g" classes.sd
