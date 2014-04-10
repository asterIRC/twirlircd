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

class ModulePassForward : public Module
{
 private:
	std::string srv, srvgecos;

 public:
	void init()
	{
		OnRehash(NULL);
		Implementation eventlist[] = { I_OnWhoisLine };
		ServerInstance->Modules->Attach(eventlist, this, sizeof(eventlist)/sizeof(Implementation));
	}

	Version GetVersion()
	{
		return Version("Hides /WHOIS 312", VF_VENDOR);
	}

	void OnRehash(User* user)
	{
		ConfigTag* tag = ServerInstance->Config->ConfValue("whoishide");
		srv = tag->getString("server", "*.*");
		srvgecos = tag->getString("gecos", "Please tell your network's admin that your network is misconfigured. Thanks! :)");
	}

	ModResult OnWhoisLine(User* fro, User* to, int &numeric, std::string &text) {
		if (numeric != 312) return MOD_RES_ALLOW;
		if (IS_OPER(fro)) return MOD_RES_ALLOW;
		text = "";
		text.append(fro->nick);
		text.append(" ");
		text.append(srv);
		text.append(" :");
		text.append(srvgecos);
		return MOD_RES_ALLOW;
	}
};

MODULE_INIT(ModulePassForward)
