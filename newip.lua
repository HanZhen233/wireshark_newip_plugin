require "bit32"
do
	-- 将每层级的地址转化成标准形式
	local function ninet_ntop(addrbytes)
		local offset=0;
		local addr,tmp,word="","",""
		local addrlen=addrbytes:len()
		local zero_seg,hex_seen,not_zero,zero_num=0,0,0,0
		if(addrlen<3) then
			addr=addr..addrbytes:tohex()
			return addr
		end
		if(addrlen%2==1) then
			addr=addrbytes:subset(offset,1):tohex(true)..":"
			offset=offset+1
		end
		while(offset<addrlen)
		do
			word=addrbytes:subset(offset,1):tohex(true)
			if(word~="00") then 
				tmp=tmp..word
				not_zero=1
			elseif(word=="00" and not_zero==1 )	then
				tmp=tmp..word
			else
				zero_num = zero_num+1
			end
			hex_seen = hex_seen+1
			offset = offset+1
			if(hex_seen==2) then
				if(zero_num == 2 and zero_seg == -1) then
					tmp="0000"
				end
				if(zero_num == 2 and zero_seg ~= -1) then
					zero_seg=zero_seg+1
				elseif(zero_seg>0 and zero_num<2) then
					if(offset==addrlen) then
						addr=addr..":"..tmp
					else
						addr=addr..":"..tmp..":"
					end 
				elseif(zero_seg<=0) then
					if(offset==addrlen) then
						addr=addr..tmp
					else
						addr=addr..tmp..":"
					end 
				end
				word,tmp="",""
				zero_num,hex_seen,not_zero=0,0,0
			end 
				
		end

		return addr
	end
	-- 展示newip地址
	local function showAddress(buf, offset, source_length)
		local index = offset 
		local endIndex = offset + source_length - 1
		local level = buf(index,1):uint()
		-- local addr = ninet_ntop(buf(index+1,level):tvb())
		local addr = ninet_ntop(buf:bytes(index+1,level))  
		local naddr = ""..addr
		local i=index+level+1
		while(i<endIndex)
		do
			level=buf(i,1):uint()
			-- addr=ninet_ntop(buf(i+1,level):tvb())
			addr=ninet_ntop(buf:bytes(i+1,level))
			i=i+level+1
			naddr=naddr.."-"..addr
		end

		return naddr
	end
	--  展示地址层级
	local function showAddressLevel(buf, offset, source_length)
		local index=offset
		local endIndex=offset+source_length-1
		local level = buf(index,1):uint()
		local i=index+level+1
		local n_level=""..level
		while(i<endIndex) 
		do
			level=buf(i,1):uint()
			i=i+level+1
			n_level=n_level.."-"..level
		end
		return n_level
	end

    --协议名称为NewIP，在Packet Details窗格显示为NewIP
    local p_NewIP = Proto("NewIP","NewIP")
	-- 目的地址
	local n_dest_address_TL = ProtoField.uint8("NewIP.dest_address_TL", "dest_address_TL", base.HEX)
	-- local n_dest_address_level = ProtoField.string("NewIP.dest_address_level", "dest_address_level", base.NONE)
	local n_dest_address = ProtoField.string("NewIP.dest_address", "dest_address", base.ASCII)
	
	-- 源地址
	local n_source_address_TL = ProtoField.uint8("NewIP.source_address_TL", "source_address_TL", base.HEX)
	-- local n_source_address_level = ProtoField.string("NewIP.source_address_level", "source_address_level", base.NONE)
	local n_source_address = ProtoField.string("NewIP.source_address", "source_address", base.ASCII)

	-- TTL
	local n_TTL = ProtoField.uint8("NewIP.TTL", "n_TTL", base.DEC)
	-- NextHeader
	local n_protocol = ProtoField.uint8("NewIP.protocol", "n_protocol", base.HEX)
	-- header_length
	local n_header_length = ProtoField.uint8("NewIP.header_length", "header_length", base.DEC)
	-- totol_length
	local n_total_length = ProtoField.uint16("NewIP.total_length", "total_length", base.DEC)
	--data
	local n_data = ProtoField.bytes("NewIP.ndata", "n_data", base.SPACE)


    --这里把NewIP协议的全部字段都加到p_NewIP这个变量的fields字段里
	p_NewIP.fields = {n_dest_address_TL, n_dest_address,n_source_address_TL, n_source_address, n_TTL, n_protocol,n_header_length,n_total_length,n_data}
    --这里是获取data这个解析器
    local data_dis = Dissector.get("data")
    
    local function ipn_dissector(buf,pkt,root)
		local buflen = buf:len()
		local offset = 0;
		--添加Packet Details
        local t = root:add(p_NewIP,buf)
        --在Packet List窗格的Protocol列可以展示出协议的名称
        pkt.cols.protocol = "NewIP"
	

		-- 目标地址
		-- 目标地址标识符及长度
		local v_dest_address_TL = buf(offset, 2)
		local temp_dest_address_TL = buf(offset, 2):uint()
		local dest_address_type = buf(offset,1):uint()
		offset = offset + 1
        local dest_address_length = buf(offset, 1):uint()
        local dest_address_TL_to_show = "Destination Address Type: "..string.format("%#x",dest_address_type).."  Destination Address Length: "..dest_address_length
		t:add(n_dest_address_TL, v_dest_address_TL, temp_dest_address_TL, dest_address_TL_to_show)
		offset = offset + 1
		-- 目标地址及层级
		local v_dest_address = buf(offset, dest_address_length)
		local temp_dest_address = buf(offset, dest_address_length):string()
		local dest_address_toshow = "Destination Address: "..showAddress(buf,offset,dest_address_length ).."  Level:"..showAddressLevel(buf,offset, dest_address_length )
		-- local dest_address_toshow = "Destination Address: "..showAddress(buf,offset,dest_length)
		t:add(n_dest_address, v_dest_address, temp_dest_address, dest_address_toshow)
		offset = offset + dest_address_length 


		-- 源地址
		-- 源地址标识符及长度
		local v_source_address_TL = buf(offset, 2)
		local temp_source_address_TL = buf(offset, 2):uint()
		local source_address_type=buf(offset, 1):uint()
		offset = offset + 1
		local source_address_length = buf(offset, 1):uint()
		local source_address_TL_to_show = "Source Address Type: "..string.format("%#x",source_address_type).."  Source Address Length: "..source_address_length
		t:add(n_source_address_TL, v_source_address_TL, temp_source_address_TL, source_address_TL_to_show)
		offset = offset + 1
		-- 源地址及层级
		local v_source_address = buf(offset, source_address_length)
		local temp_source_address = buf(offset, source_address_length):string()
		local source_address_toshow = "Source Address: "..showAddress(buf,offset,source_address_length).."  Level:"..showAddressLevel(buf,offset, source_address_length)
		-- local source_address_toshow = "Source Address: "..showAddress(buf,offset,source_length)

		t:add(n_source_address, v_source_address, temp_source_address, source_address_toshow)
		offset = offset + source_address_length

		-- TTL
		local v_TTL = buf(offset,3)
		local temp_TTL = buf(offset,3):uint()
		offset = offset + 2
		local TTL_value = buf(offset,1):uint()
		local TTL_toshow = "Time To Live: "..string.format("%d",TTL_value)
		t:add(n_TTL,v_TTL,temp_TTL,TTL_toshow)
		offset = offset + 1
	
		-- next_header
		local v_protocol = buf(offset, 3)
		local temp_protocol = buf(offset, 3):uint()
		offset = offset + 2
		local protocol_value = buf(offset, 1):uint()
		-- print(temp_protocol)
		offset = offset + 1

		-- HeaderLength
		local v_header_length = buf(offset,3)
		temp_header_length = buf(offset,3):uint()
		offset = offset + 2
		local header_length_value = buf(offset,1):uint()
		local header_length_toshow = "Header Length: "..string.format("%d",header_length_value )
		
		offset = offset + 1

		-- TotalLength
		-- 先确定TotalLength值的长度
		local totol_length_length=buf(offset+1,1):uint()
		local v_total_length = buf(offset,2+totol_length_length)
		local temp_total_length = buf(offset,2+totol_length_length):uint()
		offset = offset + 2
		local total_length_value = buf(offset,totol_length_length):uint()
		local total_length_toshow = "Total Length: "..string.format("%d",total_length_value)
		offset = offset + totol_length_length

		-- 直接用头部长度来作偏移量
		offset = header_length_value 
		-- data
		local v_data = buf(offset, (buflen - offset))
		local pro_toshow = "Next Header: "..protocol_value
		if  protocol_value== 58 then
			Dissector.get("icmpv6"):call(v_data:tvb(), pkt, root)
			pro_toshow = pro_toshow.."(ICMPv6)"
		end
		if  protocol_value == 6 then 
			Dissector.get("tcp"):call(v_data:tvb(), pkt, root)
			pro_toshow = pro_toshow.."(TCP)"
		end
		if  protocol_value == 17 then
			Dissector.get("udp"):call(v_data:tvb(), pkt, root)
			pro_toshow = pro_toshow.."(UDP)"
		end

		if protocol_value ~= 58 and protocol_value ~= 6 and protocol_value ~= 17 then
			t:add(n_data, v_data)
		end
		t:add(n_protocol,v_protocol,temp_protocol,pro_toshow)
		t:add(n_header_length,v_header_length,temp_header_length,header_length_toshow)
		t:add(n_total_length,v_total_length,temp_total_length,total_length_toshow)
		pkt.cols.protocol = "NewIP"
		
		return true
    end
    
    --这段代码是目的Packet符合条件时，被Wireshark自动调用的，是p_NewIP的成员方法
    function p_NewIP.dissector(buf,pkt,root) 
        if ipn_dissector(buf,pkt,root) then
            --valid DT diagram
        else
			--data这个dissector几乎是必不可少的；当发现不是我的协议时，就应该调用data
			data_dis:call(buf,pkt,root)
			
        end
    end
    
    local ipn_encap_table = DissectorTable.get("ethertype")
	ipn_encap_table:add(0xEADD, p_NewIP)
	-- ipn_encap_table:add(0x8999, p_NewIP)
end
