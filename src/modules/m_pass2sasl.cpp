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

class ModulePassForward : public Module
{
 private:
	std::string nickrequired, forwardmsg, forwardcmd;

 public:
	void init()
	{
		OnRehash(NULL);
		Implementation eventlist[] = { I_OnUserRegister, I_OnRehash };
		ServerInstance->Modules->Attach(eventlist, this, sizeof(eventlist)/sizeof(Implementation));
	}

	Version GetVersion()
	{
		return Version("Messes up your anus XD jk it attempts to do sasl based on PASS", VF_VENDOR);
	}

	void OnRehash(User* user)
	{
		ConfigTag* tag = ServerInstance->Config->ConfValue("passforward");
		nickrequired = tag->getString("nick", "NickServ");
		forwardmsg = tag->getString("forwardmsg", "NOTICE * :*** Sending services password as an ENCAP SASL message over the network");
		forwardcmd = tag->getString("cmd", "$b64p");
	}

	ModResult OnUserRegister(LocalUser* user)
	{
		if (user->password.find(":") != std::string::npos) {
			user->WriteServ("NOTICE * :We are attempting authentication on your behalf. If granted, you will receive a \"You are now logged in\" message.");
			std::size_t found = user->password.find(':');
			parameterlist saslstart, saslmsg;
			std::string b64p, passuser, passpass;
			passuser.append(user->password.substr(0, found));
			passpass.append(user->password.substr(found+1));
			b64p.append(":");
			b64p.append(BinToBase64('\0'+passuser+'\0'+passpass));
			saslstart.push_back("*");
			saslstart.push_back("SASL");
			saslstart.push_back(user->uuid);
			saslstart.push_back("*");
			saslstart.push_back("S");
			saslstart.push_back("PLAIN");
			ServerInstance->PI->SendEncapsulatedData(saslstart);
			saslmsg.push_back("*");
			saslmsg.push_back("SASL");
			saslmsg.push_back(user->uuid);
			saslmsg.push_back("*");
			saslmsg.push_back("S");
			saslmsg.push_back(b64p);
			ServerInstance->PI->SendEncapsulatedData(saslmsg);
		}
		return MOD_RES_ALLOW;
	}
};

MODULE_INIT(ModulePassForward)
