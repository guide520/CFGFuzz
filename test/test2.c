#include <stdio.h>
#include <unistd.h>
int main()
{
	char *dest = "magicelf";
	char str[9] = {0};
	read(0,str,8);
	int loc = 0;
	if(strcmp(str,dest) != 0)
	{
		exit(0);
	}
	else
	{
		read(0,&loc,1);
		if(loc != 1)
			exit(0);
		else
			printf("bug()");
	}
	return 0;
}

