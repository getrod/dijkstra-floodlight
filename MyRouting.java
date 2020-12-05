/*******************

Team members and IDs:
Kevin Louis-Jean 5907646

Github link:
https://github.com/getrod/dijkstra-floodlight

*******************/

package net.floodlightcontroller.myrouting;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.web.serializers.DPIDSerializer;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;

import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Set;

import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.routing.RouteId;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.topology.NodePortTuple;

import org.openflow.util.HexString;
import org.openflow.util.U8;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyRouting implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	protected IDeviceService deviceProvider;
	protected ILinkDiscoveryService linkProvider;

	protected Map<Long, IOFSwitch> switches;
	protected Map<Link, LinkInfo> links;
	protected Collection<? extends IDevice> devices;
	protected Map<Long, List<NodePortTuple>> adjacentSwitches;	//<Mac Address, Adjacent Switches>

	protected static int uniqueFlow;
	protected ILinkDiscoveryService lds;
	protected IStaticFlowEntryPusherService flowPusher;
	protected boolean printedTopo = false;

	@Override
	public String getName() {
		return MyRouting.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN)
				&& (name.equals("devicemanager") || name.equals("topology")) || name
					.equals("forwarding"));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IDeviceService.class);
		l.add(ILinkDiscoveryService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		deviceProvider = context.getServiceImpl(IDeviceService.class);
		linkProvider = context.getServiceImpl(ILinkDiscoveryService.class);
		flowPusher = context
				.getServiceImpl(IStaticFlowEntryPusherService.class);
		lds = context.getServiceImpl(ILinkDiscoveryService.class);

	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// Print the topology if not yet.
		if (!printedTopo) {
			System.out.println("*** Print topology");
			// For each switch, print its neighbor switches.
			switches = floodlightProvider.getAllSwitchMap();
			adjacentSwitches = new HashMap<Long, List<NodePortTuple>>();
			links = lds.getLinks();
			
			for (Map.Entry<Long, IOFSwitch> swtch : switches.entrySet()) {
				Long switchKey = swtch.getValue().getId();
				adjacentSwitches.put(switchKey, new ArrayList<NodePortTuple>());
				
				for (Map.Entry<Link,LinkInfo> link : links.entrySet()) { 
					// Find each outgoing link of the switch
					if(link.getKey().getSrc() != swtch.getValue().getId())
						continue;
					
					Long destMac = link.getKey().getDst();
					int destPort = link.getKey().getDstPort();
					
					adjacentSwitches.get(switchKey).add(new NodePortTuple(destMac, destPort));
				}
			}
			
			// Print topology
			for (Map.Entry<Long, List<NodePortTuple>> swtch : adjacentSwitches.entrySet()) {
				System.out.print("switch " + swtch.getKey() + " neighbors: ");
				List<NodePortTuple> verticies = swtch.getValue();
				
				for (NodePortTuple v : verticies) {
					System.out.print(v.getNodeId() + ", ");
				}
				System.out.println();
			}
			printedTopo = true;
		}


		// eth is the packet sent by a switch and received by floodlight.
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		

		// We process only IP packets of type 0x0800.
		if (eth.getEtherType() != 0x0800) {
			return Command.CONTINUE;
		}
		else{
			System.out.println("*** New flow packet");
			
			// Parse the incoming packet.
			OFPacketIn pi = (OFPacketIn)msg;
			OFMatch match = new OFMatch();
		    match.loadFromPacket(pi.getPacketData(), pi.getInPort());	

			// Calculate the path using Dijkstra's algorithm.
	        int srcIP = match.getNetworkSource();
	        int dstIP = match.getNetworkDestination();
			
	        System.out.println("srcIP: " + ipToString(match.getNetworkSource()));
	        System.out.println("dstIP: " + ipToString(match.getNetworkDestination()));
	        
			LinkedList<NodePortTuple> switchPorts = dijkstraPath(srcIP, dstIP);
			
			// Install path from destination back to source
//			Long swId = sw.getId();
//			Short swPort;
//			
//			
//			switchPorts.addLast(new NodePortTuple(sw.getId(), sw.getgetPorts().toArray()[0].portNumber));
			RouteId id = new RouteId(switchPorts.getFirst().getNodeId(), switchPorts.getLast().getNodeId());
			Route route = new Route(id, switchPorts);
			
			// Write the path into the flow tables of the switches on the path.
			if (route != null) {
				installRoute(route.getPath(), match);
			}
			
			return Command.STOP;
		}
	}
	
	private LinkedList<NodePortTuple> dijkstraPath (int srcIp, int destIp) {
		// Get srcIp and destIp's entry switches
		SwitchPort srcEntry = getDeviceEntrySwitch(srcIp);
		SwitchPort destEntry = getDeviceEntrySwitch(destIp);
		
		if(srcEntry == null || destEntry == null) return null;
		
		Long srcSw = srcEntry.getSwitchDPID();
		Long destSw = destEntry.getSwitchDPID();
		
		Map<Long, Long> distances = new HashMap<Long, Long>();			// <Mac Address, Link Distance>
		Map<Long, Long> previousVertecies = new HashMap<Long, Long>();	// <Mac Address, Mac Address>
		Set<Long> unvisited = new HashSet<Long>();						// <Mac Address>
		
		// Initialize distance to infinity and previousVertex to null
		for(Map.Entry<Long, IOFSwitch> swtch : switches.entrySet()) {
			Long swMac = swtch.getValue().getId();
			unvisited.add(swMac);
			distances.put(swMac, Long.MAX_VALUE);
			previousVertecies.put(swMac, null);
		}
		
		// Set src switch distance to 0
		distances.put(srcSw, 0L);
		
		Long currentSw = srcSw;
		while(!unvisited.isEmpty()) {
			// Visit the vertex that has the smallest known distance from the start vertex
			Long minDistance = Long.MAX_VALUE;
			for (Long v : unvisited) {
				Long currentDistance = distances.get(v);
				if (currentDistance < minDistance) {
					currentSw = v;
					minDistance = currentDistance;
				}
			}
			
			// For each adjacent vertex:
			List<NodePortTuple> adjacentList = adjacentSwitches.get(currentSw); 
			for (NodePortTuple v : adjacentList) {
				// Get link distance
				Long newDistance = distances.get(currentSw) + getSwitchLinkDistance(currentSw, v.getNodeId());
				Long currentDistance = distances.get(v.getNodeId());
				// If new distance is less than current:
				if (newDistance < currentDistance) {
					// update distance map 
					distances.put(v.getNodeId(), newDistance);
					// update previousVertex map
					previousVertecies.put(v.getNodeId(), currentSw);
				}
			}
			
			// Remove current vertex from unvisited
			unvisited.remove(currentSw);
		}
		
		// Select shortest path from srcSw to destSw
		// Tuples will be added in pairs of [<currentSw, in-port>, <currentSw, out-port>]
		LinkedList<NodePortTuple> pathStack = new LinkedList<NodePortTuple>();
		currentSw = destSw;
		Long prevSw = previousVertecies.get(currentSw);
		Long nextSw = null;
		
		
//		NodePortTuple in = new NodePortTuple(currentSw, inPort);
//		NodePortTuple out = new NodePortTuple(currentSw, outPort);
//		
//		pathStack.push(out);
//		pathStack.push(in);
//		
//		nextSw = currentSw;
//		currentSw = prevSw;
//		prevSw = previousVertecies.get(currentSw);
		
		// Create path information
		while(currentSw != null) {
			// Find currentSw dest port for prevSw link
//			int port = 0;
//			List<NodePortTuple> adjacentList = adjacentSwitches.get(prevSw); 
//			for (NodePortTuple v : adjacentList) {
//				if (v.getNodeId() == currentSw) {
//					port = v.getPortId();
//				}
//			}
			int inPort;
			int outPort;
			
			if (currentSw == destSw) {
				inPort = getLink(prevSw, currentSw).getDstPort();
				outPort = destEntry.getPort();
			} else if (currentSw == srcSw) {
				inPort = srcEntry.getPort();
				outPort = getLink(currentSw, nextSw).getSrcPort();
			} else {
				inPort = getLink(prevSw, currentSw).getDstPort();
				outPort = getLink(currentSw, nextSw).getSrcPort();
			}
			   
			NodePortTuple in = new NodePortTuple(currentSw, inPort);
			NodePortTuple out = new NodePortTuple(currentSw, outPort);
			
			pathStack.push(out);
			pathStack.push(in);
			
			nextSw = currentSw;
			currentSw = prevSw;
			prevSw = previousVertecies.get(currentSw);
		}
		
//		NodePortTuple in = new NodePortTuple(currentSw, srcEntry.getPort());
//		NodePortTuple out = new NodePortTuple(currentSw, getLink(currentSw, nextSw).getSrcPort());
//		
//		// Add source at the top of stack
//		pathStack.push(new NodePortTuple(srcSw, srcEntry.getPort()));
		
		// Print it
		System.out.println("route: ");
		for (NodePortTuple v : pathStack) {
			System.out.println("Sw: " + v.getNodeId() 
				+ "p: " + v.getPortId());
		}
		System.out.println();
		
		// Add source at the bottom of stack
		// pathStack.addLast(new NodePortTuple(srcSw, srcEntry.getPort()));
		
		return pathStack;
	}
	
	private Long getSwitchLinkDistance(long srcMac, long dstMac) {
		// If both switches have even id's, link cost is 100
		if (srcMac % 2L == 0 && dstMac % 2L == 0) {
			return 100L;
		} 
		// If both switches have odd id's, link cost is 1
		else if (srcMac % 2L != 0 && dstMac % 2L != 0) {
			return 1L;
		}
		// Otherwise, 10
		return 10L;
	}
	
	
	private SwitchPort getDeviceEntrySwitch(int deviceIp) {
		// Find the devices's first entry switch
		devices = deviceProvider.getAllDevices();
		for (IDevice device : devices) {
			if (device.getIPv4Addresses()[0] == deviceIp) {
				return device.getAttachmentPoints()[0];
			}
		}
		return null;
	}
	
	private Link getLink(long srcMac, long dstMac) {
		for (Map.Entry<Link,LinkInfo> entry : links.entrySet()) { 
			Link link = entry.getKey();
			if(link.getSrc() == srcMac && link.getDst() == dstMac) {
				return link;
			}
		}
		return null;
	}
	
	protected static String ipToString(int ip) {
        return Integer.toString(U8.f((byte) ((ip & 0xff000000) >> 24)))
               + "." + Integer.toString((ip & 0x00ff0000) >> 16) + "."
               + Integer.toString((ip & 0x0000ff00) >> 8) + "."
               + Integer.toString(ip & 0x000000ff);
    }

	// Install routing rules on switches. 
	private void installRoute(List<NodePortTuple> path, OFMatch match) {

		OFMatch m = new OFMatch();

		m.setDataLayerType(Ethernet.TYPE_IPv4)
				.setNetworkSource(match.getNetworkSource())
				.setNetworkDestination(match.getNetworkDestination());

		for (int i = 0; i <= path.size() - 1; i += 2) {
			short inport = path.get(i).getPortId();
			m.setInputPort(inport);
			List<OFAction> actions = new ArrayList<OFAction>();
			OFActionOutput outport = new OFActionOutput(path.get(i + 1)
					.getPortId());
			actions.add(outport);

			OFFlowMod mod = (OFFlowMod) floodlightProvider
					.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
			mod.setCommand(OFFlowMod.OFPFC_ADD)
					.setIdleTimeout((short) 0)
					.setHardTimeout((short) 0)
					.setMatch(m)
					.setPriority((short) 105)
					.setActions(actions)
					.setLength(
							(short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
			flowPusher.addFlow("routeFlow" + uniqueFlow, mod,
					HexString.toHexString(path.get(i).getNodeId()));
			uniqueFlow++;
		}
	}
}
