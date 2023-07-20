package ghidranes.mappers;

import java.util.Arrays;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidranes.NesRom;
import ghidranes.errors.UnimplementedNesMapperException;
import ghidranes.util.MemoryBlockDescription;

public abstract class NesMapper {
	private static final int romPermissions = 
			MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;
	private static final int sramPermissions =
			MemoryBlockDescription.READ | MemoryBlockDescription.WRITE | MemoryBlockDescription.EXECUTE;

	public abstract void updateMemoryMapForRom(NesRom rom, Program program, TaskMonitor monitor) 
		throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException;

	public static NesMapper getMapper(int mapperNum) throws UnimplementedNesMapperException {
		// Mappers are grouped by where, not how, they map PRG ROM.
		// So even though MMC3 and VRC2 may use different registers to
		// bank switch, because they organize them as 8K blocks, we
		// can treat them the same here.

		switch (mapperNum) {
			// 16K or 32K fixed PRG ROM
		case 0:   	// NROM
		case 3:   	// CNROM
		case 13:	// CPROM
			return new NromMapper();

			// 16K bankable PRG ROM
		case 1:		// MMC1 - SxROM
		case 2:		// UxROM
		case 10:	// FxROM
		case 16,30,67,68:
			return new MMC1Mapper();
		
			// 32K bankable PRG ROM
		case 7:   	// AxROM
		case 11:	//  ColorDreams
		case 34:	// BNROM, NINA-001
		case 38:
		case 66:  	// GxROM
		case 140:
			return new AxROMMapper();

			// 8K bankable PRG ROM
		case 4:		// MMC3 - TxROM
		case 18:	// Jaleco SS 88006
		case 19:	// Namco 163
		case 21,22,23,25:	// Konami VRC2/4
		case 64:	// RAMBO-1
		case 65:
		case 69:	// Sunsoft FME-7/5B
		case 74:
		case 76:	// Namco 109 variant
		case 88,95:
		case 118:	// MMC3 - TxSROM
		case 119:	// MMC3 - TQROM
		case 154,158,191,192,194,195:
		case 206:	// DxROM
		case 207:
			return new MMC3Mapper();

			// 8K/16K bankable PRG ROM
		//case 24,26:	// Konami VRC6
		//	return new VRC6Mapper();
		
			// 8K, 16K, or 8K/16K bankable PRG ROM
		//case 5:	// MMC5 - ExROM
		//	return new MMC5Mapper();

		default:
			throw new UnimplementedNesMapperException(mapperNum);
		}
	}

	protected void addPrgRamMapping(Program program, NesRom rom)
			throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		// default case - 8K PRG RAM at 0x6000
		addPrgRamMapping(program, rom, 0x6000, 0x2000);
	}

	protected void addPrgRamMapping(Program program, NesRom rom, long start, long length)
			throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
	
		// TODO: ines header ram size is not reliable.  once ines2 header is supported,
		//       should leverage that field instead.
		//if (rom.header.getPrgRamSizeBytes > 0) {
			MemoryBlockDescription.uninitialized(start, length, "SRAM", sramPermissions, false)
				.create(program);
		//}
	}

	protected void addPrgRomMapping(Program program, long start, long length, String name, 
			byte[] rombankBytes, Boolean isOverlay, TaskMonitor monitor)
			throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {

		MemoryBlockDescription.initialized(start, length, name, romPermissions, rombankBytes, isOverlay, monitor)
			.create(program);
	}

	protected void create32KBanks(Program program, NesRom rom, TaskMonitor monitor, Boolean firstBankIsDefault)
		throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {
		// 32K banks mapped from 0x8000-0xFFFF.  firstBankIsDefault controls whether the
		// first or last bank is the "primary" (i.e. not an overlay) and gets the benefit
		// of namespaceless shorter labels.

		int bankCount = rom.prgRom.length / 0x8000;
		int defaultBank = firstBankIsDefault ? 0 : bankCount - 1;

		for (int bank = 0; bank < bankCount; bank++) {
			byte[] rombankBytes = Arrays.copyOfRange(rom.prgRom, bank*0x8000, (bank+1)*0x8000);
			addPrgRomMapping(program, 0x8000, 0x8000, 
				"PRG" + bank, rombankBytes, (bank != defaultBank), monitor);
		}
	}

	protected void create16KBanks(Program program, NesRom rom, TaskMonitor monitor, Boolean firstBankIsDefault)
		throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException	{
		// 16K banks mapped from 0x8000-0xBFFF or 0xC000-0xFFFF.  firstBankIsDefault controls whether the
		// first or last bank is the "primary" (i.e. not an overlay) and gets the benefit
		// of namespaceless shorter labels.

		int bankCount = rom.prgRom.length / 0x4000;
		int defaultBank = firstBankIsDefault ? 0 : bankCount - 1;

		for (int bank = 0; bank < bankCount; bank++) {
			byte[] rombankBytes = Arrays.copyOfRange(rom.prgRom, bank*0x4000, (bank+1)*0x4000);
			addPrgRomMapping(program, 0x8000, 0x4000, 
				"PRG" + bank, rombankBytes, (bank != defaultBank), monitor);
			addPrgRomMapping(program, 0xC000, 0x4000, 
				"PRG" + bank + "_MIRROR", rombankBytes, (bank != defaultBank), monitor);
		}

	}
}
