/*
 * Author: TeYen Liu
 *
 * Copyright (C) 2013 TeYen Liu
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include <assert.h>
#include <inttypes.h>
#include "trema.h"
#include "simple_restapi_manager.h"
#include "json.h"



list_element *switches;
int send_uds_flow(uint64_t datapath_id, char* request_data,int len);
int set_oxm_matches_from_json(oxm_matches* match,char* request_data);
uint64_t dpid_from_string(char* input);


/********************************
 * convert dpif (string form) to int
 * ex: 00:33:44:55:22:55 -> 220189762133
 *
 *******************************/

uint64_t dpid_from_string(char* input){
    char *buf;
    uint64_t num = 0;
    buf = strtok(input,":");
    while(buf!=NULL){
        int a = strtol(buf,NULL,16);
        num = (num<<8) + a;
        buf = strtok(NULL,":");
    }
	return num;
}





/******************************************************************
 *  _     ___ _   _ _  __  _     ___ ____ _____
 * | |   |_ _| \ | | |/ / | |   |_ _/ ___|_   _|
 * | |    | ||  \| | ' /  | |    | |\___ \ | |
 * | |___ | || |\  | . \  | |___ | | ___) || |
 * |_____|___|_| \_|_|\_\ |_____|___|____/ |_|
 *
 *****************************************************************/


static void
create_switches( list_element **switches ) {
  create_list( switches );
}


static void
delete_switches( list_element *switches ) {
  list_element *element;
  for ( element = switches; element != NULL; element = element->next ) {
    if ( element->data != NULL ) {
      xfree( element->data );
    }
  }
  delete_list( switches );
}


static void 
insert_datapath_id( list_element **switches, uint64_t datapath_id ) {
  list_element *element = NULL;
  for ( element = *switches; element != NULL; element = element->next ) {
    if ( *( ( uint64_t * ) element->data ) > datapath_id ) {
      break;
    }
    if ( *( ( uint64_t * ) element->data ) == datapath_id ) {
      // already exists
      return;
    }
  }
  uint64_t *new = xmalloc( sizeof( uint64_t ) );
  *new = datapath_id;
  if ( element == NULL ) {
    append_to_tail( switches, new );
  }
  else if ( element == *switches ) {
    insert_in_front( switches, new );
  }
  else {
    insert_before( switches, element->data, new );
  }
}


static void
delete_datapath_id( list_element **switches, uint64_t datapath_id ) {
  list_element *element = NULL;
  for ( element = *switches; element != NULL; element = element->next ) {
    if ( *( ( uint64_t * ) element->data ) == datapath_id ) {
      void *data = element->data;
      delete_element( switches, data );
      xfree( data );
      return;
    }
  }
  // not found
}






/***************************************************
 *  _     _____    _    ____  _   _   ______        _____ _____ ____ _   _
 * | |   | ____|  / \  |  _ \| \ | | / ___\ \      / /_ _|_   _/ ___| | | |
 * | |   |  _|   / _ \ | |_) |  \| | \___ \\ \ /\ / / | |  | || |   | |_| |
 * | |___| |___ / ___ \|  _ <| |\  |  ___) |\ V  V /  | |  | || |___|  _  |
 * |_____|_____/_/   \_\_| \_\_| \_| |____/  \_/\_/  |___| |_| \____|_| |_|
 *
 *******************************************/


typedef struct {
  struct key {
    uint8_t mac[ OFP_ETH_ALEN ];
    uint64_t datapath_id;
  } key;
  uint32_t port_no;
  time_t last_update;
} forwarding_entry;


time_t
now() {
  return time( NULL );
}


/********************************************************************************
 * packet_in event handler
 ********************************************************************************/

static const int MAX_AGE = 300;


static bool
aged_out( forwarding_entry *entry ) {
  if ( entry->last_update + MAX_AGE < now() ) {
    return true;
  }
  else {
    return false;
  };
}


static void
age_forwarding_db( void *key, void *forwarding_entry, void *forwarding_db ) {
  if ( aged_out( forwarding_entry ) ) {
    delete_hash_entry( forwarding_db, key );
    xfree( forwarding_entry );
  }
}


static void
update_forwarding_db( void *forwarding_db ) {
  foreach_hash( forwarding_db, age_forwarding_db, forwarding_db );
}


static void
learn( hash_table *forwarding_db, struct key new_key, uint32_t port_no ) {
  forwarding_entry *entry = lookup_hash_entry( forwarding_db, &new_key );

  if ( entry == NULL ) {
    entry = xmalloc( sizeof( forwarding_entry ) );
    memcpy( entry->key.mac, new_key.mac, OFP_ETH_ALEN );
    entry->key.datapath_id = new_key.datapath_id;
    insert_hash_entry( forwarding_db, &entry->key, entry );
  }
  entry->port_no = port_no;
  entry->last_update = now();
}


static void
do_flooding( packet_in packet_in, uint32_t in_port ) {
  openflow_actions *actions = create_actions();
  append_action_output( actions, OFPP_ALL, OFPCML_NO_BUFFER );

  buffer *packet_out;
  if ( packet_in.buffer_id == OFP_NO_BUFFER ) {
    buffer *frame = duplicate_buffer( packet_in.data );
    fill_ether_padding( frame );
    packet_out = create_packet_out(
      get_transaction_id(),
      packet_in.buffer_id,
      in_port,
      actions,
      frame
    );
    free_buffer( frame );
  }
  else {
    packet_out = create_packet_out(
      get_transaction_id(),
      packet_in.buffer_id,
      in_port,
      actions,
      NULL
    );
  }
  send_openflow_message( packet_in.datapath_id, packet_out );
  free_buffer( packet_out );
  delete_actions( actions );
}


static void
send_packet( uint32_t destination_port, packet_in packet_in, uint32_t in_port ) {
  openflow_actions *actions = create_actions();
  append_action_output( actions, destination_port, OFPCML_NO_BUFFER );

  openflow_instructions *insts = create_instructions();
  append_instructions_apply_actions( insts, actions );

  oxm_matches *match = create_oxm_matches();
  set_match_from_packet( match, in_port, NULL, packet_in.data );

  buffer *flow_mod = create_flow_mod(
    get_transaction_id(),
    get_cookie(),
    0,
    1,  //table id
    OFPFC_ADD,
    60,
    0,
    OFP_HIGH_PRIORITY,
    packet_in.buffer_id,
    0,
    0,
    OFPFF_SEND_FLOW_REM,
    match,
    insts
  );
  send_openflow_message( packet_in.datapath_id, flow_mod );
  free_buffer( flow_mod );
  delete_oxm_matches( match );
  delete_instructions( insts );

  if ( packet_in.buffer_id == OFP_NO_BUFFER ) {
    buffer *frame = duplicate_buffer( packet_in.data );
    fill_ether_padding( frame );
    buffer *packet_out = create_packet_out(
      get_transaction_id(),
      packet_in.buffer_id,
      in_port,
      actions,
      frame
    );
    send_openflow_message( packet_in.datapath_id, packet_out );
    free_buffer( packet_out );
    free_buffer( frame );
  }

  delete_actions( actions );
}


static void
handle_packet_in( uint64_t datapath_id, packet_in message ) {
  if ( message.data == NULL ) {
    error( "data must not be NULL" );
    return;
  }
  if ( !packet_type_ether( message.data ) ) {
    return;
  }

  uint32_t in_port = get_in_port_from_oxm_matches( message.match );
  if ( in_port == 0 ) {
    return;
  }

  struct key new_key;
  packet_info packet_info = get_packet_info( message.data );
  memcpy( new_key.mac, packet_info.eth_macsa, OFP_ETH_ALEN );
  new_key.datapath_id = datapath_id;
  hash_table *forwarding_db = message.user_data;
  learn( forwarding_db, new_key, in_port );

  struct key search_key;
  memcpy( search_key.mac, packet_info.eth_macda, OFP_ETH_ALEN );
  search_key.datapath_id = datapath_id;
  forwarding_entry *destination = lookup_hash_entry( forwarding_db, &search_key );

  if ( destination == NULL ) {
    do_flooding( message, in_port );
  }
  else {
    send_packet( destination->port_no, message, in_port );
  }
}


/********************************************************************************
 * Start learning_switch controller.
 ********************************************************************************/

static const int AGING_INTERVAL = 5;


unsigned int
hash_forwarding_entry( const void *key ) {
  return hash_mac( ( ( const struct key * ) key )->mac );
}


bool
compare_forwarding_entry( const void *x, const void *y ) {
  const forwarding_entry *ex = x;
  const forwarding_entry *ey = y;
  return ( memcmp( ex->key.mac, ey->key.mac, OFP_ETH_ALEN ) == 0 )
           && ( ex->key.datapath_id == ey->key.datapath_id );
}


static void
handle_switch_ready( uint64_t datapath_id, void *user_data ) {
  UNUSED( user_data );
  info( "%#" PRIx64 " is connected.", datapath_id );
  //add datapath
  list_element **switches = user_data;
  insert_datapath_id( switches, datapath_id );
  
  openflow_actions *actions = create_actions();
  append_action_output( actions, OFPP_CONTROLLER, OFPCML_NO_BUFFER );

  openflow_instructions *insts = create_instructions();
  append_instructions_apply_actions( insts, actions );

  buffer *flow_mod = create_flow_mod(
    get_transaction_id(),
    get_cookie(),
    0,
    1, //table id = 1
    OFPFC_ADD,
    0,
    0,
    OFP_LOW_PRIORITY,
    OFP_NO_BUFFER,
    0,
    0,
    OFPFF_SEND_FLOW_REM,
    NULL,
    insts
  );
  send_openflow_message( datapath_id, flow_mod );
  free_buffer( flow_mod );
  delete_instructions( insts );
  delete_actions( actions );
}


/**************************************
 *  ____  _____ ____ _____ _____ _   _ _          _    ____ ___
 * |  _ \| ____/ ___|_   _|  ___| | | | |        / \  |  _ \_ _|
 * | |_) |  _| \___ \ | | | |_  | | | | |       / _ \ | |_) | |
 * |  _ <| |___ ___) || | |  _| | |_| | |___   / ___ \|  __/| |
 * |_| \_\_____|____/ |_| |_|    \___/|_____| /_/   \_\_|  |___|
 *
 *********************************************/

/*** Define your REST API callback function here ***/
static char *
handle_query_add_uds( const struct mg_request_info *request_info, void *request_data, int len ) {
  char dpid[30];
  memset(dpid,0,sizeof(dpid));
  memcpy(dpid,&request_info->uri[9],strlen(request_info->uri)-8);
  send_uds_flow(dpid_from_string(dpid),request_data,len);
  return "It is from test rest api...";
}

static char *
handle_query_add_uds_all( const struct mg_request_info *request_info, void *request_data,int len ) {
  UNUSED(request_info);
  int err;
  const list_element *element;
  for ( element = switches; element != NULL; element = element->next ) {
      err = send_uds_flow( *(uint64_t*)element->data,request_data,len);
	  switch(err){
		case -1:
			return "json format error\n";
		case 0:
			break;
	  }
  }
  return "send uds flow\n";
}


int send_uds_flow(uint64_t datapath_id, char* request_data,int len){
	int err = 0;
	UNUSED(len);   
	openflow_instructions *insts = create_instructions();
	append_instructions_goto_table(insts,1);

	oxm_matches *match = create_oxm_matches();
	err = set_oxm_matches_from_json(match,request_data);
	if(-1 == err){
		goto error;
	}
  
	buffer *flow_mod = create_flow_mod(
		get_transaction_id(),
		get_cookie(),
		0,
		0,  //table id
		OFPFC_ADD,
		0,
		0,
		OFP_HIGH_PRIORITY,
		0, 
		0,
		0,
		OFPFF_SEND_FLOW_REM,
		match,
		insts
		);
	send_openflow_message( datapath_id, flow_mod );

	free_buffer( flow_mod );

error:
	delete_oxm_matches( match );
	delete_instructions( insts );
	return err;
}

int set_oxm_matches_from_json(oxm_matches* oxm_match,char* request_data){
	int err = 0;
	json_object *new_obj,*match;
	json_object *data1,*data2;
	char eth_mac[OFP_ETH_ALEN],eth_mac_mask[OFP_ETH_ALEN];
    new_obj = json_tokener_parse(request_data);
	if(!json_object_object_get_ex(new_obj,"match",&match)){
		printf("parse match filed  error %s\n",json_object_get_string(new_obj));
  		err = -1;
		goto error;
	}
    if(json_object_object_get_ex(match,"eth_src",&data1)){
		sscanf(json_object_get_string(data1), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth_mac[0], &eth_mac[1], &eth_mac[2], &eth_mac[3], &eth_mac[4], &eth_mac[5]);
		json_object_put(data1);
		//Get eth_mac_mask
		if(json_object_object_get_ex(match,"eth_src_mask",&data2)){
			sscanf(json_object_get_string(data2), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth_mac_mask[0], &eth_mac_mask[1], &eth_mac_mask[2], &eth_mac_mask[3], &eth_mac_mask[4], &eth_mac_mask[5]);
			json_object_put(data2);
		}	
		else{
			memset(eth_mac_mask,255,sizeof(eth_mac_mask));
		}
		append_oxm_match_eth_src(oxm_match,(uint8_t*)eth_mac,(uint8_t*)eth_mac_mask);
	}
    if(json_object_object_get_ex(match,"eth_dst",&data1)){
		sscanf(json_object_get_string(data1), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth_mac[0], &eth_mac[1], &eth_mac[2], &eth_mac[3], &eth_mac[4], &eth_mac[5]);
		json_object_put(data1);
		//Get eth_mac_mask
		if(json_object_object_get_ex(match,"eth_dst_mask",&data2)){
			sscanf(json_object_get_string(data2), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth_mac_mask[0], &eth_mac_mask[1], &eth_mac_mask[2], &eth_mac_mask[3], &eth_mac_mask[4], &eth_mac_mask[5]);
			json_object_put(data2);
		}	
		else{
			memset(eth_mac_mask,255,sizeof(eth_mac_mask));
		}
		append_oxm_match_eth_dst(oxm_match,(uint8_t*)eth_mac,(uint8_t*)eth_mac_mask);
	}

error:
	json_object_put(new_obj);
	return err;
}

/***************************************************/


int
main( int argc, char *argv[] ) {
  
  /* Initialize the Trema world */
  init_trema( &argc, &argv );
  
  create_switches( &switches );
  /* Init restapi manager */
  init_restapi_manager();
  
  /* Start restapi manager */
  start_restapi_manager();
  
  /*** Add your REST API ***/
  add_restapi_url( "^/uds/add/all$", "PUT", handle_query_add_uds_all );
  add_restapi_url( "^/uds/add/", "PUT", handle_query_add_uds );
  /*************************/
  
  /* Set switch ready handler  (learning switch)*/
  hash_table *forwarding_db = create_hash( compare_forwarding_entry, hash_forwarding_entry );
  add_periodic_event_callback( AGING_INTERVAL, update_forwarding_db, forwarding_db );
  set_packet_in_handler( handle_packet_in, forwarding_db );
  set_switch_ready_handler( handle_switch_ready, &switches );

  /* Main loop */
  start_trema();

  /* Finalize transaction manager */
  finalize_restapi_manager();

  return 0;
}



/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
