global timer_modbus1 = F;
global timer_modbus2 = F;
global timer_modbus3 = F;
global precond_1 = F;
global timer_period_MODBUS1 = 0.4 secs;
global precond_2 = F;
global timer_period_MODBUS2 = 0.4 secs;
global precond_3 = F;
global timer_period_MODBUS3 = 0.4 secs;
global VSD1_Command_Word2 = 0;
global modbus_inject_counter_1 = 0;
global modbus_inject_counter_2 = 0;
global modbus_inject_counter_3 = 0;
event timer_finish_MODBUS1()
{
	if (timer_modbus1 == T) 
	{
		print "Deletion/Delay alarm for SCADA_Q2C_Sync_Activated";
		timer_modbus1 = F;
	}
}
event timer_finish_MODBUS2()
{
	if (timer_modbus2 == T) 
	{
		print "Deletion/Delay alarm for Q2C_In_Sync";
		timer_modbus2 = F;
	}
}
event timer_finish_MODBUS3()
{
	if (timer_modbus3 == T) 
	{
		print "Deletion/Delay alarm for SCADA_Q2C_Close";
		timer_modbus3 = F;
	}
}

event write_request(c: connection, domainID: string, itemID: string, boolean_result: bool)
{
	if (itemID == "GGIO17$CO$SPCSO2$Oper")
	{
		if (c$id$orig_h == 172.18.5.60)
		{
			precond_1 = boolean_result;
			if (precond_1 == T)
			{
				if (timer_modbus1 != T) 
				{
					timer_modbus1 = T;
					schedule timer_period_MODBUS1 {timer_finish_MODBUS1()};
				}
			}
		}
	}
	if (itemID == "MIED2_V16GGIO1$ST$Ind3$stVal")
	{
		if (c$id$orig_h == 172.16.4.41)
		{
			precond_2 = boolean_result;
			if (precond_2 == T)
			{
				if (timer_modbus2 != T) 
				{
					timer_modbus2 = T;
					schedule timer_period_MODBUS2 {timer_finish_MODBUS2()};
				}
			}
		}
	}
	if (itemID == "GGIO17$CO$SPCSO9$Oper")
	{
		if (c$id$orig_h == 172.18.5.60)
		{
			precond_3 = boolean_result;
			if (precond_3 == T)
			{
				if (timer_modbus3 != T) 
				{
					timer_modbus3 = T;
					schedule timer_period_MODBUS3 {timer_finish_MODBUS3()};
				}
			}
		}
	}
}

event read_response(c: connection, invokeID: count, itemID: string, boolean_result: bool)
{
	if (itemID == "GGIO17$CO$SPCSO2$Oper")
	{
		if (c$id$orig_h == 172.18.5.60)
		{
			precond_1 = boolean_result;
			if (precond_1 == T)
			{
				if (timer_modbus1 != T) 
				{
					timer_modbus1 = T;
					schedule timer_period_MODBUS1 {timer_finish_MODBUS1()};
				}
			}
		}
	}
	if (itemID == "MIED2_V16GGIO1$ST$Ind3$stVal")
	{
		if (c$id$orig_h == 172.16.4.41)
		{
			precond_2 = boolean_result;
			if (precond_2 == T)
			{
				if (timer_modbus2 != T) 
				{
					timer_modbus2 = T;
					schedule timer_period_MODBUS2 {timer_finish_MODBUS2()};
				}
			}
		}
	}
	if (itemID == "GGIO17$CO$SPCSO9$Oper")
	{
		if (c$id$orig_h == 172.18.5.60)
		{
			precond_3 = boolean_result;
			if (precond_3 == T)
			{
				if (timer_modbus3 != T) 
				{
					timer_modbus3 = T;
					schedule timer_period_MODBUS3 {timer_finish_MODBUS3()};
				}
			}
		}
	}
}

event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders, start_address: count, registers: ModbusRegisters)
{
	VSD1_Command_Word2=registers[0];
	if (precond_1 == T)
	{
		modbus_inject_counter_1=modbus_inject_counter_1 + 1;
		if (VSD1_Command_Word2==7502)
		{
			timer_modbus1 = F;
			break;
		}
		timer_modbus1 = F;
		print "Modification Alarm for SCADA_Q2C_Sync_Activated";
	}
	if (modbus_inject_counter_1 > 1)
	{
		print "Modbus injection attack for SCADA_Q2C_Sync_Activated";
		modbus_inject_counter_1 = 0;
	}
	if (precond_2 == T)
	{
		modbus_inject_counter_2=modbus_inject_counter_2 + 1;
		if (VSD1_Command_Word2==7500)
		{
			timer_modbus2 = F;
			break;
		}
		timer_modbus2 = F;
		print "Modification Alarm for Q2C_In_Sync";
	}
	if (modbus_inject_counter_2 > 1)
	{
		print "Modbus injection attack for Q2C_In_Sync";
		modbus_inject_counter_2 = 0;
	}
	if (precond_3 == T)
	{
		modbus_inject_counter_3=modbus_inject_counter_3 + 1;
		if (VSD1_Command_Word2==7500)
		{
			timer_modbus3 = F;
			break;
		}
		timer_modbus3 = F;
		print "Modification Alarm for SCADA_Q2C_Close";
	}
	if (modbus_inject_counter_3 > 1)
	{
		print "Modbus injection attack for SCADA_Q2C_Close";
		modbus_inject_counter_3 = 0;
	}
}
