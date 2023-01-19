// (C) 2019 University of NKU. Free for used
// Author: stoneboat@mail.nankai.edu.cn

/*
* client_core.h
*
*/

#include <string>
#include <array>
#include <vector>
#include <atomic>
#include <fstream>
#include <map>
#include <pthread.h>
#include <string>
#include "../App/Tools/utils.h"



/*
*	@class client_core
*	@functionality basic functionality of client
*	@Params of the Class client_core
*		@PREP_DATA_PREFIX   The position where the local data of client is stored 
*		@transfer_buffer	the buffer waiting for transfer block
*/
// extern int att;

class client_core{
private:
	int nthreads;
	int mynumber;

	std::vector<size_t> sent_bytes;

	// for multi-thread
	pthread_mutex_t mutex_go;
  	int thread_Go;
  	size_t *X;

public:
	client_core(int argc, const char** argv);
	~client_core();

	void start(size_t *X,size_t len);
	void init();
	void attestation();

	/*
	* basic communication functionality
	*/
	// receive from client thread_num
	void receive_from(int thread_num, uint8_t* data, size_t& data_len) const;

	// Send to client thread_num
	void send_to(int thread_num, uint8_t* data, size_t data_len);

	size_t report_size();


private:
	std::string PREP_DATA_PREFIX;

	/*
	*	Network part
	*/
	int pnbase;
	std::string hostname;
	std::vector<int> socket_num;

	std::vector<uint8_t*> transfer_buffer;
	std::vector<size_t>	  transfer_ptr;
};