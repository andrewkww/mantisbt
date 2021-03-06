<?php
# MantisBT - A PHP based bugtracking system
# Copyright (C) 2002 - 2010  MantisBT Team - mantisbt-dev@lists.sourceforge.net
# MantisBT is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# MantisBT is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MantisBT.  If not, see <http://www.gnu.org/licenses/>.

form_security_validate( 'plugin_format_config_edit' );

auth_reauthenticate( );
access_ensure_global_level( config_get( 'manage_plugin_threshold' ) );

$f_process_text = gpc_get_int( 'process_text', ON );
$f_process_urls = gpc_get_int( 'process_urls', ON );
$f_process_buglinks = gpc_get_int( 'process_buglinks', ON );

if( plugin_config_get( 'process_text' ) != $f_process_text ) {
	plugin_config_set( 'process_text', $f_process_text );
}

if( plugin_config_get( 'process_urls' ) != $f_process_urls ) {
	plugin_config_set( 'process_urls', $f_process_urls );
}

if( plugin_config_get( 'process_buglinks' ) != $f_process_buglinks ) {
	plugin_config_set( 'process_buglinks', $f_process_buglinks );
}

form_security_purge( 'plugin_format_config_edit' );

print_successful_redirect( plugin_page( 'config', true ) );
