/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2009 Daniel De Graaf <danieldg@inspircd.org>
 *   Copyright (C) 2008 Craig Edwards <craigedwards@brainbox.cc>
 *   Copyright (C) 2007 Robin Burchell <robin+git@viroteck.net>
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


#include "inspircd.h"

/* $ModDesc: Provides usermode +k to protect services from kicks, kills and mode changes. */

/** Handles user mode +k
 */
class ServProtectMode : public ModeHandler
{
 public:
	ServProtectMode(Module* Creator) : ModeHandler(Creator, "operprotect", 'q', PARAM_NONE, MODETYPE_USER) { oper = true; }

	ModeAction OnModeChange(User* source, User* dest, Channel* channel, std::string &parameter, bool adding)
	{
		return MODEACTION_ALLOW;
		/* Because this returns MODEACTION_DENY all the time, there is only ONE
		 * way to add this mode and that is at client introduction in the UID command,
		 * as this calls OnModeChange for each mode but disregards the return values.
		 * The mode cannot be manually added or removed, not even by a server or by a remote
		 * user or uline, which prevents its (ab)use as a kiddie 'god mode' on such networks.
		 * I'm sure if someone really wants to do that they can make a copy of this module
		 * that does the job. It won't be me though!
		 */
	}
};

class ModuleServProtectMode : public Module
{
	ServProtectMode bm;
 public:
	ModuleServProtectMode()
		: bm(this)
	{
	}

	void init()
	{
		ServerInstance->Modules->AddService(bm);
		Implementation eventlist[] = { I_OnWhois, I_OnWhoisLine, I_OnRawMode, I_OnUserPreKick, I_OnPreMode };
		ServerInstance->Modules->Attach(eventlist, this, sizeof(eventlist)/sizeof(Implementation));
	}


	~ModuleServProtectMode()
	{
	}

	Version GetVersion()
	{
		return Version("Provides usermode +k to protect services from kicks, kills, and mode changes.", VF_VENDOR);
	}

	void OnWhois(User* src, User* dst)
	{
		if (dst->IsModeSet('q'))
		{
			ServerInstance->SendWhoisLine(src, dst, 310, src->nick+" "+dst->nick+" :is a protected oper and may not be kicked from channels.");
		}
	}

	ModResult OnRawMode(User* user, Channel* chan, const char mode, const std::string &param, bool adding, int pcnt)
	{
		/* Check that the mode is not a server mode, it is being removed, the user making the change is local, there is a parameter,
		 * and the user making the change is not a uline
		 */
		if (!adding && chan && IS_LOCAL(user) && !param.empty() && !ServerInstance->ULine(user->server))
		{
			/* Check if the parameter is a valid nick/uuid
			 */
			User *u = ServerInstance->FindNick(param);
			if (u)
			{
				Membership* memb = chan->GetUser(u);
				/* The target user has +k set on themselves, and you are trying to remove a privilege mode the user has set on themselves.
				 * This includes any prefix permission mode, even those registered in other modules, e.g. +qaohv. Using ::ModeString()
				 * here means that the number of modes is restricted to only modes the user has, limiting it to as short a loop as possible.
				 */
				if (u->IsModeSet('q'))
				{
					/* BZZZT, Denied! */
					user->WriteNumeric(482, "%s %s :Cannot kick, kill or deop a protected oper", user->nick.c_str(), chan->name.c_str()/*, ServerInstance->Config->Network.c_str()*/);
					return MOD_RES_DENY;
				}
			}
		}
		/* Mode allowed */
		if (user->IsModeSet('q'))
		{	return MOD_RES_ALLOW;
		} else return MOD_RES_PASSTHRU;
	}

	ModResult OnPreMode(User* source,User* dest,Channel* channel, const std::vector<std::string>& parameters)
	{
		if (source->IsModeSet('q'))
		{	return MOD_RES_ALLOW;
		} else return MOD_RES_PASSTHRU;
	}

	ModResult OnUserPreKick(User *src, Membership* memb, const std::string &reason)
	{
		if (memb->user->IsModeSet('q'))
		{
			src->WriteNumeric(484, "%s %s :Cannot kick, kill or deop a protected oper.",
				src->nick.c_str(), memb->chan->name.c_str());
			return MOD_RES_DENY;
		} else return MOD_RES_PASSTHRU;
	}
};


MODULE_INIT(ModuleServProtectMode)
