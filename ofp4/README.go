/*
Package ofp4 implements openflow 1.3 protocol structures.

ofp4 structs implement encoding.BinaryMarshaler and encoding.BinaryUnmarshaler 
interfaces.

Examples:
 var message ofp4.Message
 err := message.UnmarshalBinary(data []byte)
 fmt.Println(message.Type) // ofp_header.type
*/
package ofp4