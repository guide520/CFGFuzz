#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
int main(int argc, char **argv)
{
	char buf[2014];
	int fp, size;
	struct stat s;
	if((fp = open(argv[1], O_RDONLY)) == -1)
		exit(0);
	fstat(fp,&s);
	size = s.st_size;
	//Check1
	if(size > 1024 || size < 60)
	{
		close(fp);
		return -1;
	}
	read(fp,buf,size);
	//Check2
	if(strcmp(&buf[0],"magicefl",8) == 0)
	{
		//Check3
		if(strcmp(&buf[10],"gifkasdf",8) == 0)
		{
			printf("23333");
			close(fp);
			return 0;
		}
		else
		{
			printf("1111");
		}
	}
	close(fp);
	return -1;
}

