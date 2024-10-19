package utils

import (
	"fmt"
	"testing"
)

func TestAESTools_AesDecryptCBC(t *testing.T) {
	body := "fu+/vQLvv70Bbu+/vXjvvy82YhiAU4hFx31bUh7oC4q75qlto0cxgDR+FbTNKjBKWx7MhdvBYTJFbov+mLeJbyYfV9iKOp1mOqVRceMd7ryj7m2v0ac/NrfcCs3f14CcqJAY2lwA5i2Ur9CovDF4Px73dlxwisc92dY+C79N8L6DEcwpwVxfNB0kMbsvGaUFtIGtw1V9MxS/rGYRf9EuEsXB0VkbDHloZtmiAc1S00gw/622kF/ttN4dGzUdSO9dTJcQZCcsv/nwrOnhgr9CwpujHVjBwZYCid/J9j0YQdI5dkuk9Dwn9CcYgQsYT3/Wsd4lyZx0IJPVUt6IeYqISJ3Sw4QttX56dAdu6ORgBEen9g5AZ/onvoU9CeCyTCM+CLrCzRoVIvIEcLGVJU9xK4wkZdUGoH64B4hv5rfn6f01RGjUv4AyypyVHtfuA32SJhAbAvBXZ9bLgk5tzbTvHLVY0MW0C1tW/Bm5pqdKaxJAQljdAc1QVD5PVkmV4EVeWDimSK5Ps679IOVM+I0yAT3UK+QjpNnqh73NFhSRj+sH8/xmICOqTvrlJtvj0PrXW5myE8VAOOhSU3EGJx5AYCbgQV4gdw1Qk9nsRGg12ILRMHSSmI9/dEtxPtkgkK6TCtMKGQsCWSlZTdW9W9eMs4tkocfWMyCY+q35jjWqtt5qZ3e9jB9hUHa2uDNhM2vQiVluxc/PMGKzo3ancrKv6Q=="
	var key string = "64544A12A1F147A4A6A73534A125836A"
	tool := NewDefaultAESTools()
	s, err := tool.Decrypt(body, key)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(s)
}
