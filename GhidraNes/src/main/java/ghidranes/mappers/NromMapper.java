package ghidranes.mappers;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidranes.NesRom;

public class NromMapper extends NesMapper {
	@Override
	public void updateMemoryMapForRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		// standard PRG RAM
		addPrgRamMapping(program, rom);

		if (rom.prgRom.length < 0x8000) {
			// 16K PRG ROM 0x8000-0xBFFF mirrored at 0xC000-0xFFFF
			create16KBanks(program, rom, monitor, true);
		} else {
			// 32K PRG ROM 0x8000-0xFFFF
			create32KBanks(program, rom, monitor, true);
		}
	}
}
