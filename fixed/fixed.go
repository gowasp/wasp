package fixed

type Fixed byte

const (
	Fixed_CONNECT   Fixed = iota + 1 // 连接
	Fixed_CONNACK                    // 连接回复
	Fixed_PUBLISH                    // 发布
	Fixed_PUBACK                     // 发布回复
	Fixed_PING                       // ping
	Fixed_PONG                       // pong
	Fixed_SUBSCRIBE                  // 订阅
	Fixed_SUBACK                     // 订阅回复
	Fixed_UNSUBSCRIBE
	Fixed_UNSUBACK
	Fixed_FORWARD
)
