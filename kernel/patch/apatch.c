
#include "linux/module.h"
int apatch_init(void)
{


	//patch();


    
	return 0;
}

void apatch_exit(void)
{

	return;
}

module_init(apatch_init);
module_exit(apatch_exit);

//MODULE_LICENSE("GPL");
//MODULE_AUTHOR("");
//MODULE_DESCRIPTION("Apatch inject file");

