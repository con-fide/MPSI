// (C) 2019 University of NKU. Free for used
// Author: stoneboat@mail.nankai.edu.cn

/*
* server_core.h
*
*/
#include "../Tools/utils.h"
#include "../Networking/ServerSocket.h"
#include "../Tools/time-func.h"
#include <string>
#include <vector>
#include <pthread.h>



class server_core{
private:
	int nthreads;
	int pnbase;
	int nclients;

	// for multi-thread
	pthread_mutex_t mutex_go;
  	int thread_Go;
  	size_t **re_X;

public:
	void start(int client_no);
	void init(int client_no,size_t *X_i,size_t len_i);
	void attestation();

	server_core(int argc, const char** argv,size_t **X,size_t *len);
	~server_core();

	mutable std::vector<ServerSocket*> server;
	std::vector<int> socket_num;

	/*
	* basic communication functionality
	*/
	// receive an octetstream from client thread_num
	void receive_from(int thread_num, uint8_t* data, size_t& data_len) const;

	// Send an octetStream to client thread_num
	void send_to(int thread_num, uint8_t* data, size_t data_len) const;

	//template <typename T>
// 	inline void pack (std::vector< uint8_t >& dst, size_t& data) {
//     uint8_t * src = static_cast < uint8_t* >(static_cast < void * >(&data));
//     dst.insert (dst.end (), src, src + sizeof (size_t));
// }   

	//template <typename T>
	// inline void unpack (vector <uint8_t >& src, int index, size_t& data) {
	//     copy (&src[index], &src[index + sizeof (size_t)], &data);
	// }

private:
	std::string PREP_DATA_PREFIX;
	// remain the communication load
	mutable size_t sent;
};