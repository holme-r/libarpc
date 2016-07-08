ACLOCAL_AMFLAGS = -I m4

SUBDIRS = build arpcgen libarpc arpcbind arpcinfo test

# Set the order for the subdirs
libarpc: build 
arpcbind: build libarpc
arpcinfo: build libarpc
test: build libarpc
