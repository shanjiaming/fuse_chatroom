#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>

#define CreateMapType(v) \
struct Node_##v;\
typedef struct Node_##v *Nodeptr_##v;\
struct Node_##v {\
    const char *key;\
    v val;\
    Nodeptr_##v fa;\
    Nodeptr_##v left;\
    Nodeptr_##v right;\
};\
\
\
typedef Nodeptr_##v Map_##v;\
\
\
Nodeptr_##v find_##v(Map_##v map, const char *key) {\
    int cmp = map->key == NULL ? -1 : strcmp(key, map->key);\
    if (cmp == 0) return map;\
    if (cmp < 0) {       \
        if(!map->left) return NULL;                \
        return find_##v(map->left, key);\
    }\
    if (cmp > 0) {       \
        if(!map->right) return NULL;                  \
        return find_##v(map->right, key);\
    }\
    return NULL;\
}                        \
\
int insert_##v(Map_##v map, const char *key, v val) {\
    int cmp = map->key == NULL ? -1 : strcmp(key, map->key);\
    if (cmp == 0) return 0;\
    if (cmp < 0) {\
        if (map->left == NULL) {\
            Nodeptr_##v tmp = malloc(sizeof(struct Node_##v));\
            tmp->key = key;\
            tmp->val = val;\
            tmp->fa = map;\
            tmp->left = NULL;\
            tmp->right = NULL;\
            map->left = tmp;\
            return 1;\
        }\
        return insert_##v(map->left, key, val);\
    }\
    if (cmp > 0) {\
        if (map->right == NULL) {\
            Nodeptr_##v tmp = malloc(sizeof(struct Node_##v));\
            tmp->key = key;\
            tmp->val = val;\
            tmp->fa = map;\
            tmp->left = NULL;\
            tmp->right = NULL;\
            map->right = tmp;\
            return 1;\
        }\
        return insert_##v(map->right, key, val);\
    }\
    return 999;\
}\
\
Nodeptr_##v next_##v(Nodeptr_##v ptr) {\
    if (ptr->left) return ptr->left;\
    if (ptr->right) return ptr->right;\
    while (ptr->fa) {\
        if (ptr->fa->left == ptr && ptr->fa->right != NULL) {\
            return ptr->fa->right;\
        }\
        ptr = ptr->fa;\
    }\
    return NULL;\
}\
Nodeptr_##v init_##v(Nodeptr_##v ptr) {              \
    return next_##v(ptr);                                 \
}                                 \
Map_##v make_map_##v() {\
    Nodeptr_##v tmp = malloc(sizeof(struct Node_##v));\
    tmp->key = NULL;\
    tmp->fa = NULL;\
    tmp->left = NULL;\
    tmp->right = NULL;\
    return tmp;\
}



typedef struct {
	char *contents;
	size_t maxsize;
	size_t len;
	struct timespec st_atim;
	struct timespec st_mtim;
} Fcontent;


typedef Fcontent* F;

CreateMapType(F);


typedef Map_F D;

CreateMapType(D);

static Map_D dirs;



static struct options {
	int show_help;
} options;


#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};




static void *chat_init(struct fuse_conn_info *conn,
			struct fuse_config *cfg)
{
	(void) conn;
	cfg->kernel_cache = 1;
	return NULL;
}

static Nodeptr_D get_dir_ptr_dd(const char *path){
	char* deli = strchr(path+1,'/');
	size_t len = deli - path - 1;
	char* p = malloc(len+1);
	p[len] = '\0';
	strncpy(p,path+1, len);
	Nodeptr_D dptr = find_D(dirs, p);
	free(p);
	return dptr;
}

static F getF(const char *path){
	Nodeptr_D dptr = get_dir_ptr_dd(path);
	if (!dptr) {
		return NULL;
	}
	
	Nodeptr_F f = find_F(dptr->val, strchr(path+1,'/')+1);
	if (!f) {
		return NULL;
	}
	return f->val;
}

static int is_valid_filepath(const char *path){
	if(*path != '/'){
		return 0;
	}
	char* deli = strchr(path+1,'/');
	if(!deli){
		return 0;
	}
	if(strchr(deli+1,'/')){
		return 0;
	}
	if(!get_dir_ptr_dd(path)){
		return 0;
	}
	if(!find_D(dirs, deli+1)){
		return 0;
	}
	return 1;
}


static int chat_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi)
{
    (void) fi;
    int res = 0;


    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else if (find_D(dirs,path+1)){
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 1;
    } else if (is_valid_filepath(path)){
        F f = getF(path);
        if(!f){
            res = -ENOENT;
        }else{
            stbuf->st_mode = S_IFREG | 0666;
            stbuf->st_nlink = 1;
            stbuf->st_size = f->len;
			stbuf->st_atim = f->st_atim;
			stbuf->st_mtim = f->st_mtim;
        }
    }else{
        res = -ENOENT;
    }
    return res;
}

static int chat_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;

	if (strcmp(path, "/") == 0){
		for (Nodeptr_D dir = init_D(dirs); dir; dir = next_D(dir)) {
			filler(buf, dir->key, NULL, 0, 0);
    	}
		filler(buf, ".", NULL, 0, 0);
		filler(buf, "..", NULL, 0, 0);
		return 0;
	}

	if(strchr(path+1,'/')) {
		return -ENOENT;
	}
	Nodeptr_D dptr = find_D(dirs, path+1);
	if(!dptr){
		return -ENOENT;
	}
	for (Nodeptr_F f = init_F(dptr->val); f; f = next_F(f)){
		filler(buf, f->key, NULL, 0, 0);
	}
	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);
	

	return 0;
}

void file_create(const char *path){
	//path will change afterwards
	char* str = strdup(path + 1);
	const char s[2] = "/";
	char *token_a = strtok(str, s);
	char *token_b = strtok(NULL, s);   

	Nodeptr_D dptr_a = find_D(dirs, token_a);
	Nodeptr_D dptr_b = find_D(dirs, token_b);
	
	assert(dptr_a && dptr_b);

	F f = malloc(sizeof(Fcontent));
	f->contents = malloc(0);
	f->maxsize = 1;
	f->len = 0;
	//memory leak
	insert_F(dptr_a->val, token_b, f);
	insert_F(dptr_b->val, token_a, f);
}

// static int File_Descriptor = 3;

static int chat_open(const char *path, struct fuse_file_info *fi)
{	
	return 0;
	if(!is_valid_filepath(path)){
		return -ENOENT;
	}
	F f = getF(path);
	if (!f){
		if((fi->flags & O_ACCMODE) == O_RDONLY){
			return -EACCES;
		}else{
			file_create(path);
			return 0;
		}
	}
/*
	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;
*/
	return 0;
}

static int file_read(F f, char *buf, size_t size, off_t offset)
{
    if (offset < f->len) {
        if (offset + size > f->len){
            size = f->len - offset;
		}
        memcpy(buf, f->contents + offset, size);
    } else{
        size = 0;
	}
    return size;
}


static int chat_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi)
{
    (void) fi;
	if(!is_valid_filepath(path)){
		return -ENOENT;
	}
	F f = getF(path);
	if (!f){
        return -ENOENT;
	}
	return file_read(f, buf, size, offset);
}






static void double_maxsize(F f){
    f->maxsize *= 2;
    char* tmp = f->contents;
    char* doublespase = malloc(f->maxsize);
    memcpy(doublespase, tmp, f->len);
    free(tmp);
	f->contents = doublespase;
}

static int file_write(F f, const char *buf, size_t size, off_t offset)
{
    while(offset + size > f->maxsize){
        double_maxsize(f);
    }

	if(f->len < offset + size){
		f->len = offset + size;
	}

    memcpy(f->contents + offset, buf, size);
    return size;
}


static int chat_write(const char *path, const char *buf, size_t size,
                      off_t offset, struct fuse_file_info *fi)
{
    (void) fi;
	
	if(!is_valid_filepath(path)){
		return -ENOENT;
	}
	F f = getF(path);
	if (!f){
        return -ENOENT;
	}

	return file_write(f, buf, size, offset);
}


int chat_create (const char *path, mode_t mode, struct fuse_file_info *fi){
	(void) fi;
	(void) mode;

	if(!is_valid_filepath(path)){
		return -ENOENT;
	}
	file_create(path);
	return 0;

}

static int chat_mkdir(const char *path, mode_t mode)
{
	(void)mode;
	if(*path != '/' || strchr(path+1,'/')) {
		return -errno;
	}
	insert_D(dirs, strdup(path+1), make_map_F());
	return 0;
}

static int chat_utimens(const char* path, const struct timespec tv[2], struct fuse_file_info *fi) {
    F f = getF(path);
	f->st_atim = tv[0];
	f->st_mtim = tv[1];
    return 0;
}

static const struct fuse_operations chat_oper = {
	.init		= chat_init,
	.getattr	= chat_getattr,
	.readdir	= chat_readdir,
	.open		= chat_open,
	.read		= chat_read,
	.write		= chat_write,
	.create		= chat_create,
	.mkdir		= chat_mkdir,
	.utimens 	= chat_utimens,
};

static void show_help(const char *progname)
{
	printf("FUSE chatroom created by stella\n");
	printf("usage: %s [options] <mountpoint>\n\n", progname);
	printf("#demo:"
		   "cd <mountpoint>"
		   "mkdir bot1 #to create a user named bot1\n"
	       "ls bot1    #and you can use ls to see who are bot1 chatting with\n"
	       "mkdir bot2 #create another user\n"
	       "echo \"bot1:hello,bot2!\" >> bot1/bot2 #send message\n"
	       "cat bot2/bot1 #show message received by bot2\n"
		   "\n\n");
}

int main(int argc, char *argv[])
{
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	dirs = make_map_D();

	/* Parse options */
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return 1;

	/* When --help is specified, first print our own file-system
	   specific help text, then signal fuse_main to show
	   additional help (by adding `--help` to the options again)
	   without usage: line (by setting argv[0] to the empty
	   string) */
	if (options.show_help) {
		show_help(argv[0]);
		assert(fuse_opt_add_arg(&args, "--help") == 0);
		args.argv[0][0] = '\0';
	}

	ret = fuse_main(args.argc, args.argv, &chat_oper, NULL);
	fuse_opt_free_args(&args);
	return ret;
}
