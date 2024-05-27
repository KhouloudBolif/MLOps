import pefile
import math

def extract_pe_info(file_path):
    # Load the PE file
    pe = pefile.PE(file_path)

    # Extract basic information
    info = {
        'DOS Header': pe.DOS_HEADER.dump_dict(),
        'NT Headers': pe.NT_HEADERS.dump_dict(),
        'File Header': pe.FILE_HEADER.dump_dict(),
        'Optional Header': pe.OPTIONAL_HEADER.dump_dict(),
        'Sections': [section.dump_dict() for section in pe.sections],
    }

    # Extract imports
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        info['Imports'] = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_info = {
                'DLL': entry.dll.decode('utf-8'),
                'Imports': []
            }
            for imp in entry.imports:
                dll_info['Imports'].append({
                    'Name': imp.name.decode('utf-8') if imp.name else None,
                    'Address': hex(imp.address)
                })
            info['Imports'].append(dll_info)

    # Extract exports
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        info['Exports'] = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            info['Exports'].append({
                'Name': exp.name.decode('utf-8') if exp.name else None,
                'Address': hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
                'Ordinal': exp.ordinal
            })

    return info
def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    length = len(data)
    frequency = [0] * 256
    for byte in data:
        frequency[byte] += 1
    for count in frequency:
        if count == 0:
            continue
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def extract_specific_features(file_path):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)

        # Extract specific features
        specific_features = {
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
          'Machine': pe.FILE_HEADER.Machine,
            'Characteristics': pe.FILE_HEADER.Characteristics,
           'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
           
           'SectionsMaxEntropy': max([section.get_entropy() for section in pe.sections]) if pe.sections else 0,
           'VersionInformationSize': len(pe.FileInfo) if hasattr(pe, 'FileInfo') else 0,
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'ResourcesMaxEntropy':0,
            'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
           
            'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
           
              'ResourcesMinEntropy' :0	,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            #'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            
           
            'SectionsMinEntropy' :0,
           'SectionsMeanEntropy' :0
        }
  # Calculer les entropies pour les sections
        section_entropies = [calculate_entropy(section.get_data()) for section in pe.sections if section.get_data()]
        specific_features['SectionsMinEntropy'] = min(section_entropies) if section_entropies else 0
        specific_features['SectionsMeanEntropy'] = sum(section_entropies) / len(section_entropies) if section_entropies else 0

        # Calculer les entropies pour les ressources
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            resource_entropies = []
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if entry.directory:
                    for subentry in entry.directory.entries:
                        if subentry.data:
                            resource_data = subentry.data.get_data()
                            if resource_data:
                                entropy = calculate_entropy(resource_data)
                                resource_entropies.append(entropy)
            specific_features['ResourcesMinEntropy'] = min(resource_entropies) if resource_entropies else 0
            specific_features['ResourcesMaxEntropy'] = max(resource_entropies) if resource_entropies else 0

        return specific_features

    except pefile.PEFormatError as e:
        print(f"Error loading PE file: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

# Example usage
file_path = 'C:/Users/khoul/Dropbox/PC/Downloads/eclipse-java-2024-03-R-win32-x86_64/eclipse/eclipsec.exe'
specific_features = extract_pe_info(file_path)

 #Print the extracted features if extraction was successful
if specific_features:
    import pprint
    pprint.pprint(specific_features)
#else:
   #  print("Failed to extract features from the PE file.")
