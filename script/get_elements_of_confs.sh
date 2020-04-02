CONF_DIR=$1;
shift;
OUT_DIR=$1;

CONF_LIST=`find $CONF_DIR | grep click$`;

for fn in $CONF_LIST; do
    bn=`basename $fn .click`;
    echo $bn;
    python3 script/get_element_list.py $fn > $OUT_DIR/$bn-elements;
done;
