/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2010 Daniel De Graaf <danieldg@inspircd.org>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


/* $ModDesc: Forwards a password users can send on connect (for example for NickServ identification). */

#include "inspircd.h"
#include "hash.h"
#include <cstring>

class ModulePassForward : public Module
{
 private:
	std::string nickrequired, forwardmsg, forwardcmd, seperator, b64result;
	std::string::size_type pch;

 public:
	void init()
	{
		OnRehash(NULL);
		Implementation eventlist[] = { I_OnUserRegister, I_OnRehash };
		ServerInstance->Modules->Attach(eventlist, this, sizeof(eventlist)/sizeof(Implementation));
	}

	Version GetVersion()
	{
		return Version("Sends server password to services", VF_VENDOR);
	}

	void OnRehash(User* user)
	{
		ConfigTag* tag = ServerInstance->Config->ConfValue("passloc");
		nickrequired = tag->getString("nick", "NickServ");
		seperator = tag->getString("seperator", ":");
		forwardmsg = tag->getString("forwardmsg", "NOTICE $nick :*** Attempting service login to $nickrequired");
		forwardcmd = "AUTHENTICATE $b64p";
	}

	void FormatStr(std::string& result, const std::string& format, const LocalUser* user)
	{
		for (unsigned int i = 0; i < format.length(); i++)
		{
			char c = format[i];
			if (c == '$')
			{
				if (format.substr(i, 13) == "$nickrequired")
				{
					result.append(nickrequired);
					i += 12;
				}
				else if (format.substr(i, 5) == "$nick")
				{
					result.append(user->nick);
					i += 4;
				}
				else if (format.substr(i, 5) == "$user")
				{
					result.append(user->ident);
					i += 4;
				}
				else if (format.substr(i,5) == "$pass")
				{
					result.append(user->password);
					i += 4;
				}
				else if (format.substr(i,5) == "$b64p")
				{
					pch = strchr(user->password.c_str, seperator);
					b64result = "\0";
					b64result.append(user->password.substr(0,pch-1));
					b64result.append("\0");
					b64result.append(user->password.substr(pch+1));
					result.append(BinToBase64(b64result));
					i += 4;
				}
				else
					result.push_back(c);
			}
			else
				result.push_back(c);
		}
	}

	virtual void OnUserRegister(User* ruser)
	{
		LocalUser* user = IS_LOCAL(ruser);
		if (!user || user->password.empty())
			return;

		if (!nickrequired.empty())
		{
			/* Check if nick exists and its server is ulined */
			User* u = ServerInstance->FindNick(nickrequired);
			if (!u || !ServerInstance->ULine(u->server))
				return;
		}

		std::string saslplain = "AUTHENTICATE PLAIN";
		std::string tmp;
		FormatStr(tmp,forwardmsg, user);
		user->WriteServ(tmp);

		tmp.clear();
		FormatStr(tmp,forwardcmd, user);
		//ServerInstance->Parser->ProcessBuffer("CAP REQ :sasl",user);
		ServerInstance->Parser->ProcessBuffer(saslplain,user);
		ServerInstance->Parser->ProcessBuffer(tmp,user);
		//ServerInstance->Parser->ProcessBuffer("CAP END",user);
	}
};

MODULE_INIT(ModulePassForward)
