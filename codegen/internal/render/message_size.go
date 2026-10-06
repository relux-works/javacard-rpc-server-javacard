package render

func fixedMessageLength(fields []Field) (int, bool) {
	total := 0
	for _, field := range fields {
		switch field.Type {
		case FieldTypeU8, FieldTypeBool:
			total++
		case FieldTypeU16:
			total += 2
		case FieldTypeU32:
			total += 4
		case FieldTypeBytesFixed:
			if field.FixedLength <= 0 {
				return 0, false
			}
			total += field.FixedLength
		case FieldTypeASCII, FieldTypeBytes:
			if field.Length == nil || *field.Length <= 0 {
				return 0, false
			}
			total += *field.Length
		default:
			return 0, false
		}
	}
	return total, true
}
