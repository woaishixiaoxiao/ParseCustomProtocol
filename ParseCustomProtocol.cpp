#include <stdint.h>
#include <stdio.h>
#include <queue>
#include <vector>
#include <iostream>
#include <string.h>
#include <json/json.h>
#include <arpa/inet.h>  //这个是干什么的
using namespace std;

const uint8_t MY_PROTO_MAGIC = 88;//  模数用于校验信息的。
const uint32_t MY_PROTO_MAX_SIZE = 10 * 1024 * 1024;
const uint32_t MY_PROTO_HEAD_SIZE = 8;

typedef enum MyProtoParserStatus {
	ON_PARSER_INIT = 0,
	ON_PARSER_HEAD = 1,
	ON_PARSER_BODY = 2,
}MyProtoParserStatus;

/*
协议头
*/
struct MyProtoHead {
	uint8_t version;    //协议版本号
	uint8_t magic;      //协议模数
	uint16_t server;    //协议复用的服务号，表示协议之上的不同服务  可以根据此服务号，选择不同的处理函数/类
	uint32_t len;       //协议长度 协议头长度 + 变长Json协议体长度
};

/*
协议消息体
*/
struct MyProtoMsg {
	MyProtoHead head;  //协议头
	Json::Value body;  //协议体
};

void myProtoMsgPrint(MyProtoMsg& msg) {
	string jsonStr = "";
	Json::FastWriter fWriter;
	jsonStr = fWriter.write(msg.body);
	printf("Head[version=%d,magic=%d,server=%d,len=%d]\n"
        "Body:%s", msg.head.version, msg.head.magic, 
		msg.head.server, msg.head.len, jsonStr.c_str());
}

class MyProtoEncode {
	public:
		uint8_t* encode(MyProtoMsg *pMsg, uint32_t& len);
	private:
		void headEncode(uint8_t* pData, MyProtoMsg* pMsg);
};

uint8_t*  MyProtoEncode::encode(MyProtoMsg* pMsg, uint32_t& len) {
	uint8_t pData = NULL;
	Json::FastWriter fWriter;
	
	string bodyStr = fWriter.write(pMsg->body);
	len = MY_PROTO_HEAD_SIZE + (uint32_t)bodyStr.size();
	pMsg->head.len = len;
	pData = new uint8_t[len];
	
	headEncode(pData, pMsg);
	memcpy(pData + MY_PROTO_HEAD_SIZE, bodyStr.data(), bodyStr.size());
	
	return pData;
}

void MyProtoEncode::headEncode(uint8_t* pData, MyProtoMsg* pMsg) {
	*pData = 1;
	++pData;
	
	*pData = MY_PROTO_MAGIC;
	++pData;
	
	*(uint16_t *)pData = htons(pMsg->head.server);
	pData += 2;
	
	*(uint32_t*)pData = htonl(pMsg->head.len);
}

/*
   MyProto解包类
*/
class MyProtoDecode {
	public:
		void init();
		void clear();
		bool parse(void* data, size_t len);
		bool empty();
		MyProtoMsg* front();
		void pop();
	private:
		bool parserHead(uint8_t** curData, uint32_t& curLen, uint32_t& parserLen, bool& parserBreak);
		bool parserBody(uint8_t** curData, uint32_t& curLen, uint32_t& parserLen, bool& parserBreak);
	
	private: 
		MyProtoMsg mCurMsg;                      //当前解析中的协议消息体
		queue<MyProtoMsg*>mMsgQ;                 //解析好的协议消息队列  这里感觉没有必要用指针啊 但是用指针最好，因为比如要访问元素，返回指针而不用进行复制操作了。
		vector<uint8_t>mCurReserved;            //未解析的网络字节流
		MyProtoParserStatus mCurParserStatus;   //当前解析的状态。
};

void MyProtoDecode::init() {
	mCurParserStatus = ON_PARSER_INIT;
}

void MyProtoDecode::clear() {
	MyProtoMsg *pMsg;
	
	while(!mMsgQ.epmty()) {
		pMsg = mMsgQ.front();
		delete pMsg;
		mMsgQ.pop();
	}
}

//将对端网络字节流压到数组vector中，算出当前vector的大小。
//当状态为ON_PARSER_INIT或者ON_PARSER_BODY的时候，解析头部。当状态为ON_PARSER_HAED的时候，解析BODY。
//当状态为ON_PARSER_BODY的时候，证明当前已经解析完成一个完整的包。将解析完的包压入到队列中去。
//每次解析head或者body的时候，如果当前剩余的网络字节流的大小不足本次解析，则会跳出while循环。
//最后根据parselen的大小，对mCurReserved进行删除
bool MyProtoDecode::parse(void *data, size_t len) {
	if(len < 0) {
		return false;
	}
	uint32_t curLen = 0;
	uint32_t parserLen = 0;
	uint8_t* curData = NULL;
	
	curData = (uint8_t *)data;
	while(len--) {
		mCurReserved.push_back(*curData);  //这里将内容存到了vector中去
		++curData;
	}
	curLen = mCurReserved.size();   //这里的mCurReserved的大小不一定等于len，因为可能还有之前粘包处理剩下的。
	curData = (uint8_t *)&mCurReserved[0]; //和上述同理，这里也不一定是data开头的数据
	
	while(curLen > 0) {
		bool parserBreak = false;
		if(ON_PARSER_INIT == mCurParserStatus || ON_PARSER_BODY == mCurParserStatus) {
			if(!parserHead(&curData, curLen, parserLen, parserBreak)) {
				return false;
			}
			if(parserBreak) break;
		}else {
			assert(ON_PARSER_HEAD == mCurParserStatus);
			if(!parserBody(&curData, curLen, parserLen, parserBreak)) {
				return false;
			}
			if(parserBreak) break;
		}
		if(ON_PARSER_BODY == mCurParserStatus) {
			//拷贝解析完的消息体放入队列中
			MyProtoMsg * pMsg = NULL;
			pMsg = new MyProtoMsg;
			*pMsg = mCurMsg;
			mMsgQ.push(pMsg); 
		}
	}
	if(parserLen > 0) {
		mCurReserved.erase(mCurReserved.begin(), mCurReserved.begin() + parserLen);
	}
	return true;
}

//没有一次性解析头部和消息主体，可以提高效率。都调用一次函数了，能解析的就解析。
bool MyProtoDecode::parserHead(uint8_t** curData, uint32_t& curLen, uint32_t& parserLen, bool& parserBreak) {
	parserBreak = false;
	if(curLen < MY_PROTO_HEAD_SIZE) {
		parserBreak = true;
		return true;
	}
	
	uint8_t* pData = *curData;   //遍历curData用
	mCurMsg.head.version = *pData;
	++pData;
	
	mCurMsg.head.magic = *pData;
	++pData;
	
	if(MY_PROTO_MAGIC != mCurMsg.head.magic) {
		return false;
	}
	
	mCurMsg.head.server = ntohs(*(uint16_t*)pData);
	pData += 2;
	mCurMsg.head.len = ntohl(*(uint32_t*)pData);
	
	//异常大包，则返回解析失败
    if (mCurMsg.head.len > MY_PROTO_MAX_SIZE)
    {
        return false;
    }
	
	(*curData) += MY_PROTO_HEAD_SIZE;
	curLen -= MY_PROTO_HEAD_SIZE;
	parserLen += MY_PROTO_HEAD_SIZE;
	mCurParserStatus = ON_PARSER_HEAD;
}

bool MyProtoDecode::parserBody(uint8_t** curData, uint32_t& curLen, uint32_t& parserLen, bool& parserBreak) {
	parserBreak = false;
	uint32_t jsonSize = mCurMsg.head.len - MY_PROTO_HEAD_SIZE;
    if (curLen < jsonSize)
    {
        parserBreak = true; //终止解析
        return true;
    }
	Json::Reader reader;
    if (!reader.parse((char *)(*curData), 
        (char *)((*curData) + jsonSize), mCurMsg.body, false))
    {
        return false;
    }

    //解析指针向前移动jsonSize字节
    (*curData) += jsonSize;
    curLen -= jsonSize;
    parserLen += jsonSize;
    mCurParserStatus = ON_PARSER_BODY;

    return true;
}

bool MyProtoDecode::empty() {
	return mMsgQ.empty();
}

MyProtoMsg* MyProtoDecode::front() {
	return mMsgQ.front();
}

void MyProtoDeCode::pop()
{
    mMsgQ.pop();
}

int main() {
	uint32_t len = 0;
	uint8_t* pData = NULL;
	
	MyProtoMsg msg1;
	MyProtoMsg msg2;
	MyProtoDecode myDecode;
	MyProtoDecode myEncode;
	
	msg1.head.server = 1;
	msg1.body["op"] = "set";
	msg1.body["key"] = "id";
	msg1.body["value"] = "9856";
	
	msg2.head.server = 2;
    msg2.body["op"] = "get";
    msg2.body["key"] = "id";
	
	myDecode.init();
	pData = myEncode.encode(&msg1, len); //这里不用的时候需要释放。因为不能预先知道pData所需要的长度，所以这里没办法事先创建
	
	if (!myDecode.parser(pData, len)) 
    {
        cout << "parser falied!" << endl;
    }
    else
    {
        cout << "msg1 parser successful!" << endl;
    }
	
	pData = myEncode.encode(&msg2, len);
	if (!myDecode.parser(pData, len))
    {
        cout << "parser falied!" << endl;
    }
    else
    {
        cout << "msg2 parser successful!" << endl;
    }
	
	MyProtoMsg * pMsg = NULL;
    while (!myDecode.empty())
    {
        pMsg = myDecode.front();
        myProtoMsgPrint(*pMsg);
        myDecode.pop();
    }
    
	myDecode.clear();
	delete [](uint8_t *)pData;
    return 0;
}